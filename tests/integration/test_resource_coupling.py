"""Report-only finite cross-endpoint resource coupling."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
import yaml
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.report import AnalysisReport
from fastapi_endpoint_detector.models.resource_coupling import (
    ResourceCouplingError,
    load_resource_coupling,
    semantic_hash,
)
from fastapi_endpoint_detector.output.formatters import get_formatter

if TYPE_CHECKING:
    from pathlib import Path


def _project(
    root: Path,
    *,
    mode: str = "report_only",
    changed_callsite: bool = False,
) -> tuple[Path, Path, Path]:
    (root / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "def write_state(key: str) -> None: pass\n"
        "def read_state(key: str) -> str: return key\n\n"
        "@app.post('/write')\n"
        "def writer() -> None:\n"
        "    write_state('orders:1')\n\n"
        "@app.get('/read')\n"
        "def reader() -> str:\n"
        "    return read_state('orders:1')\n",
        encoding="utf-8",
    )
    contracts = root / "effects.yaml"
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "coupling-test",
                    "version": "1.0.0",
                    "provenance": {"kind": "user", "source": "effects.yaml"},
                },
                "contracts": [
                    {
                        "id": "read-state",
                        "symbol": f"{root.name}.main.read_state",
                        "invocation": "function",
                        "operation": "read",
                        "channel": "custom",
                        "resource": {"kind": "argument", "index": 0},
                    },
                    {
                        "id": "write-state",
                        "symbol": f"{root.name}.main.write_state",
                        "invocation": "function",
                        "operation": "write",
                        "channel": "custom",
                        "resource": {"kind": "argument", "index": 0},
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    coupling = root / "coupling.yaml"
    limits = {"max_endpoint_links_per_resource": 8, "max_edges": 16}
    if mode == "changed_callsite_candidates":
        limits["max_new_candidates"] = 4
    coupling.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1 if mode == "report_only" else 2,
                "mode": mode,
                "groups": [
                    {
                        "id": "orders-state",
                        "resource_space": "orders-test-namespace",
                        "producer_contract_ids": ["write-state"],
                        "consumer_contract_ids": ["read-state"],
                    }
                ],
                "limits": limits,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    diff = root / "change.diff"
    changed_hunk = (
        "@@ -10,1 +10,1 @@\n-    write_state('orders:0')\n+    write_state('orders:1')\n"
        if changed_callsite
        else "@@ -5,1 +5,1 @@\n"
        "-def write_state(key: str) -> None: pass\n"
        "+def write_state(key: str) -> None: return None\n"
    )
    diff.write_text(
        "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n" + changed_hunk,
        encoding="utf-8",
    )
    return contracts, coupling, diff


def _candidate_projection(report: AnalysisReport) -> list[dict[str, object]]:
    return [item.model_dump(mode="json") for item in report.candidate_endpoints]


def test_report_only_graph_is_exact_and_never_changes_candidates(tmp_path: Path) -> None:
    contracts, coupling, diff = _project(tmp_path)
    base_config = Config(analysis=AnalysisConfig(effect_contracts=contracts))
    baseline = ChangeMapper(
        app_path=tmp_path,
        config=base_config,
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    mapper = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                resource_coupling=coupling,
            )
        ),
        secure_ast=True,
        use_cache=False,
    )
    configured = mapper.analyze_diff(diff)

    assert mapper.mypy_analyzer._build_result is None
    assert all(
        mapper.mypy_analyzer.get_endpoint_dependencies(endpoint) is not None
        for endpoint in mapper.inventory.endpoints
    )
    loaded_coupling = load_resource_coupling(coupling)
    normalized = loaded_coupling.document.normalized_payload()
    assert "max_new_candidates" not in normalized["limits"]
    assert loaded_coupling.config_hash == semantic_hash(normalized)
    assert _candidate_projection(configured) == _candidate_projection(baseline)
    assert configured.affected_endpoints == baseline.affected_endpoints
    assert configured.orphan_changes == baseline.orphan_changes
    graph = configured.resource_coupling_graph
    assert graph is not None
    assert graph.status == "diagnostic_only"
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.producer_contract_id == "write-state"
    assert edge.consumer_contract_id == "read-state"
    assert edge.strength.value == "exact"
    assert edge.producer_endpoint_id != edge.consumer_endpoint_id
    serialized = json.dumps(configured.model_dump(mode="json"))
    assert "orders:1" not in serialized
    assert "orders-test-namespace" not in serialized


def test_exact_added_writer_callsite_adds_one_low_nonrecursive_reader(
    tmp_path: Path,
) -> None:
    contracts, coupling, diff = _project(
        tmp_path,
        mode="changed_callsite_candidates",
        changed_callsite=True,
    )
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                resource_coupling=coupling,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert report.resource_coupling_graph is not None
    assert report.resource_coupling_graph.status == "candidate_eligible"
    candidates = {item.endpoint.path: item for item in report.candidate_endpoints}
    assert set(candidates) == {"/write", "/read"}
    assert candidates["/read"].confidence.value == "low"
    assert candidates["/read"].reason == "Potential cross-request finite resource coupling"
    evidence = candidates["/read"].resource_coupling_evidence
    assert len(evidence) == 1
    assert evidence[0].causal_basis == "exact_added_producer_callsite"
    assert evidence[0].changed_file == "main.py"
    assert evidence[0].changed_line == 10
    assert [item.endpoint.path for item in report.affected_endpoints] == ["/write"]
    json_report = json.loads(get_formatter("json").format(report))
    json_reader = next(
        item for item in json_report["candidate_endpoints"] if item["endpoint"]["path"] == "/read"
    )
    assert json_reader["resource_coupling_evidence"][0]["status"] == ("potential_cross_request")
    for output_format in ("text", "markdown", "html"):
        assert (
            "potential cross-request coupling"
            in get_formatter(output_format).format(report).lower()
        )


def test_low_threshold_presents_candidate_without_changing_graph(tmp_path: Path) -> None:
    contracts, coupling, diff = _project(
        tmp_path,
        mode="changed_callsite_candidates",
        changed_callsite=True,
    )
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                resource_coupling=coupling,
                confidence_threshold=0.3,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert {item.endpoint.path for item in report.affected_endpoints} == {"/write", "/read"}
    assert report.resource_coupling_graph is not None
    assert len(report.resource_coupling_graph.edges) == 1


def test_unrelated_writer_implementation_change_never_seeds_candidate(
    tmp_path: Path,
) -> None:
    contracts, coupling, diff = _project(
        tmp_path,
        mode="changed_callsite_candidates",
    )
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                resource_coupling=coupling,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert [item.endpoint.path for item in report.candidate_endpoints] == ["/write"]
    assert report.candidate_endpoints[0].resource_coupling_evidence == ()


def test_disjoint_or_dynamic_resources_never_fan_out(tmp_path: Path) -> None:
    contracts, coupling, diff = _project(tmp_path)
    main = tmp_path / "main.py"
    source = main.read_text(encoding="utf-8")
    main.write_text(
        source.replace("read_state('orders:1')", "read_state(key='orders:2')"),
        encoding="utf-8",
    )
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                resource_coupling=coupling,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert report.resource_coupling_graph is not None
    assert report.resource_coupling_graph.edges == ()


def test_hot_resource_component_is_omitted_atomically(tmp_path: Path) -> None:
    contracts, coupling, diff = _project(tmp_path)
    main = tmp_path / "main.py"
    main.write_text(
        main.read_text(encoding="utf-8") + "\n@app.get('/read-again')\n"
        "def reader_again() -> str:\n"
        "    return read_state('orders:1')\n",
        encoding="utf-8",
    )
    document = yaml.safe_load(coupling.read_text(encoding="utf-8"))
    document["limits"]["max_endpoint_links_per_resource"] = 1
    coupling.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                resource_coupling=coupling,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    assert report.resource_coupling_graph is not None
    assert report.resource_coupling_graph.edges == ()
    assert [item.reason_code for item in report.resource_coupling_graph.diagnostics] == [
        "resource_fanout_limit_exceeded"
    ]
    assert report.resource_coupling_graph.diagnostics[0].omitted_edges == 2


def test_candidate_overflow_aborts_atomically(tmp_path: Path) -> None:
    contracts, coupling, diff = _project(
        tmp_path,
        mode="changed_callsite_candidates",
        changed_callsite=True,
    )
    main = tmp_path / "main.py"
    main.write_text(
        main.read_text(encoding="utf-8") + "\n@app.get('/read-again')\n"
        "def reader_again() -> str:\n"
        "    return read_state('orders:1')\n",
        encoding="utf-8",
    )
    document = yaml.safe_load(coupling.read_text(encoding="utf-8"))
    document["limits"]["max_new_candidates"] = 1
    coupling.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(ResourceCouplingError, match="aborted atomically"):
        ChangeMapper(
            app_path=tmp_path,
            config=Config(
                analysis=AnalysisConfig(
                    effect_contracts=contracts,
                    resource_coupling=coupling,
                )
            ),
            secure_ast=True,
            use_cache=False,
        ).analyze_diff(diff)


def test_candidate_mode_rejects_unevaluated_package_applicability(
    tmp_path: Path,
) -> None:
    contracts, coupling, diff = _project(
        tmp_path,
        mode="changed_callsite_candidates",
        changed_callsite=True,
    )
    document = yaml.safe_load(contracts.read_text(encoding="utf-8"))
    document["contracts"][1]["package"] = {
        "distribution": "example-state",
        "version": ">=1,<2",
    }
    contracts.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(ResourceCouplingError, match="package applicability"):
        ChangeMapper(
            app_path=tmp_path,
            config=Config(
                analysis=AnalysisConfig(
                    effect_contracts=contracts,
                    resource_coupling=coupling,
                )
            ),
            secure_ast=True,
            use_cache=False,
        ).analyze_diff(diff)


def test_unknown_contract_and_operation_fail_closed(tmp_path: Path) -> None:
    contracts, coupling, diff = _project(tmp_path)
    document = yaml.safe_load(coupling.read_text(encoding="utf-8"))
    document["groups"][0]["producer_contract_ids"] = ["missing"]
    coupling.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(ResourceCouplingError, match="unknown producer"):
        ChangeMapper(
            app_path=tmp_path,
            config=Config(
                analysis=AnalysisConfig(
                    effect_contracts=contracts,
                    resource_coupling=coupling,
                )
            ),
            secure_ast=True,
            use_cache=False,
        ).analyze_diff(diff)


def test_config_requires_effect_source_and_strict_sorted_groups(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires effect"):
        AnalysisConfig(resource_coupling=tmp_path / "coupling.yaml")
    path = tmp_path / "coupling.yaml"
    path.write_text(
        "schema_version: 1\nmode: report_only\ngroups:\n"
        "  - id: b\n    resource_space: b\n    producer_contract_ids: [write]\n"
        "    consumer_contract_ids: [read]\n"
        "  - id: a\n    resource_space: a\n    producer_contract_ids: [write]\n"
        "    consumer_contract_ids: [read]\n",
        encoding="utf-8",
    )
    with pytest.raises(ResourceCouplingError, match="sorted unique"):
        load_resource_coupling(path)

    candidate_root = tmp_path / "candidate"
    candidate_root.mkdir()
    _contracts, candidate_path, _diff = _project(
        candidate_root,
        mode="changed_callsite_candidates",
        changed_callsite=True,
    )
    candidate_document = yaml.safe_load(candidate_path.read_text(encoding="utf-8"))
    candidate_document["schema_version"] = 1
    candidate_path.write_text(
        yaml.safe_dump(candidate_document, sort_keys=False),
        encoding="utf-8",
    )
    with pytest.raises(ResourceCouplingError, match="version 1"):
        load_resource_coupling(candidate_path)


def test_candidate_evidence_tampering_is_rejected(tmp_path: Path) -> None:
    contracts, coupling, diff = _project(
        tmp_path,
        mode="changed_callsite_candidates",
        changed_callsite=True,
    )
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                resource_coupling=coupling,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    payload = report.model_dump(mode="json")
    reader = next(
        item for item in payload["candidate_endpoints"] if item["endpoint"]["path"] == "/read"
    )
    reader["resource_coupling_evidence"][0]["changed_line"] = 1

    with pytest.raises(ValidationError, match="differs from graph edge"):
        AnalysisReport.model_validate(payload)

    missing_graph = report.model_dump(mode="json")
    missing_graph["resource_coupling_graph"] = None
    with pytest.raises(ValidationError, match="requires its graph"):
        AnalysisReport.model_validate(missing_graph)


def test_graph_tampering_is_rejected_and_all_formats_disclose_report_only(
    tmp_path: Path,
) -> None:
    contracts, coupling, diff = _project(tmp_path)
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                resource_coupling=coupling,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)
    payload = report.model_dump(mode="json")
    payload["resource_coupling_graph"]["edges"][0]["consumer_endpoint_id"] = f"sha256:{'0' * 64}"
    with pytest.raises(ValidationError):
        AnalysisReport.model_validate(payload)

    for output_format in ("text", "markdown", "html"):
        rendered = get_formatter(output_format).format(report)
        assert "report-only" in rendered
        assert "does not change candidates" in rendered
    assert json.loads(get_formatter("json").format(report))["resource_coupling_graph"]
    assert yaml.safe_load(get_formatter("yaml").format(report))["resource_coupling_graph"]


def _message_project(root: Path) -> tuple[Path, Path, Path]:
    (root / "main.py").write_text(
        "from fastapi import FastAPI\n\n"
        "app = FastAPI()\n\n"
        "def publish(topic: str) -> None: pass\n"
        "def consume(topic: str) -> None: pass\n\n"
        "@app.post('/publish')\n"
        "def publisher() -> None:\n"
        "    publish('orders.created')\n\n"
        "@app.post('/consume')\n"
        "def consumer() -> None:\n"
        "    consume('orders.created')\n",
        encoding="utf-8",
    )
    contracts = root / "message-effects.yaml"
    contracts.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "preset": {
                    "id": "message-coupling-test",
                    "version": "1.0.0",
                    "provenance": {"kind": "user", "source": "message-effects.yaml"},
                },
                "contracts": [
                    {
                        "id": "consume-topic",
                        "symbol": f"{root.name}.main.consume",
                        "invocation": "function",
                        "operation": "consume",
                        "channel": "message_bus",
                        "resource": {"kind": "argument", "index": 0},
                    },
                    {
                        "id": "publish-topic",
                        "symbol": f"{root.name}.main.publish",
                        "invocation": "function",
                        "operation": "publish",
                        "channel": "message_bus",
                        "resource": {"kind": "argument", "index": 0},
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    coupling = root / "message-coupling.yaml"
    coupling.write_text(
        yaml.safe_dump(
            {
                "schema_version": 2,
                "mode": "changed_callsite_candidates",
                "groups": [
                    {
                        "id": "orders-events",
                        "resource_space": "orders-message-test",
                        "producer_contract_ids": ["publish-topic"],
                        "consumer_contract_ids": ["consume-topic"],
                    }
                ],
                "limits": {
                    "max_endpoint_links_per_resource": 8,
                    "max_edges": 16,
                    "max_new_candidates": 4,
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    diff = root / "message.diff"
    diff.write_text(
        "diff --git a/main.py b/main.py\n"
        "--- a/main.py\n"
        "+++ b/main.py\n"
        "@@ -10,1 +10,1 @@\n"
        "-    publish('orders.pending')\n"
        "+    publish('orders.created')\n",
        encoding="utf-8",
    )
    return contracts, coupling, diff


def test_exact_publish_consume_edges_and_candidates(tmp_path: Path) -> None:
    contracts, coupling, diff = _message_project(tmp_path)
    report = ChangeMapper(
        app_path=tmp_path,
        config=Config(
            analysis=AnalysisConfig(
                effect_contracts=contracts,
                resource_coupling=coupling,
            )
        ),
        secure_ast=True,
        use_cache=False,
    ).analyze_diff(diff)

    graph = report.resource_coupling_graph
    assert graph is not None
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.channel.value == "message_bus"
    assert edge.producer_operation.value == "publish"
    assert edge.consumer_operation.value == "consume"
    candidates = {item.endpoint.path: item for item in report.candidate_endpoints}
    assert set(candidates) == {"/publish", "/consume"}
    assert candidates["/consume"].confidence.value == "low"
    assert len(candidates["/consume"].resource_coupling_evidence) == 1
    assert [item.endpoint.path for item in report.affected_endpoints] == ["/publish"]


def test_state_message_operation_mixing_fails_closed(tmp_path: Path) -> None:
    contracts, coupling, diff = _project(tmp_path)
    document = yaml.safe_load(contracts.read_text(encoding="utf-8"))
    document["contracts"][0]["operation"] = "consume"
    contracts.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(ResourceCouplingError, match="unsupported operation directions"):
        ChangeMapper(
            app_path=tmp_path,
            config=Config(
                analysis=AnalysisConfig(
                    effect_contracts=contracts,
                    resource_coupling=coupling,
                )
            ),
            secure_ast=True,
            use_cache=False,
        ).analyze_diff(diff)
