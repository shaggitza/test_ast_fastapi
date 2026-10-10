"""Public mapper/report integration for selected framework phase evidence."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.config import AnalysisConfig, Config
from fastapi_endpoint_detector.models.endpoint import SnapshotSide
from fastapi_endpoint_detector.models.report import AnalysisReport
from fastapi_endpoint_detector.output.json_output import JsonFormatter
from fastapi_endpoint_detector.output.yaml_output import YamlFormatter
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor

if TYPE_CHECKING:
    from pathlib import Path


def _write_app(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    app = root / "main.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.on_event('startup')\n"
        "def startup() -> None:\n"
        "    print('ready')\n",
        encoding="utf-8",
    )
    return app


def _framework_mapper(
    app: Path,
    *,
    use_scip: bool = False,
    app_entry: str | None = None,
) -> ChangeMapper:
    return ChangeMapper(
        app,
        config=Config(analysis=AnalysisConfig(surface_preset="framework-v1")),
        secure_ast=True,
        use_scip=use_scip,
        use_cache=False,
        app_entry=app_entry,
    )


def test_public_mapper_reports_phase_and_conditions_without_promoting_untyped_evidence(
    tmp_path: Path,
) -> None:
    app = _write_app(tmp_path / "target")
    mapper = _framework_mapper(app)
    assert mapper.inventory.endpoints

    report = mapper.analyze_diff("")
    phase_report = report.framework_phase_report

    assert phase_report is not None
    assert report.candidate_endpoints == report.affected_endpoints == []
    assert phase_report.snapshot_side == "target"
    assert phase_report.record_count == 1
    record = phase_report.records[0]
    assert record["phase"] == "startup"
    assert record["callback"]["symbol"] == "startup"
    assert record["status"] == "unavailable"
    assert record["typed_provider_fingerprint"] is None
    assert (
        "framework executes startup callback only when that phase is dispatched"
        in (record["execution_conditions"])
    )
    assert any(
        "retained typed provider evidence is absent" in item for item in record["limitations"]
    )
    assert phase_report.established_count == phase_report.conditional_count == 0
    assert phase_report.unavailable_count == 1
    assert mapper.map_framework_phase_report(snapshot_side=SnapshotSide.BASELINE).snapshot_side == (
        "baseline"
    )


def test_public_mapper_rejects_foreign_inventory_and_scip_without_claiming_records(
    tmp_path: Path,
) -> None:
    target_app = _write_app(tmp_path / "target")
    foreign_app = _write_app(tmp_path / "foreign")
    mapper = _framework_mapper(target_app)
    mapper._mypy_analyzer = mapper.mypy_analyzer
    _ = mapper.inventory
    foreign_inventory = CustomSurfaceExtractor(
        foreign_app.parent,
        mapper._surface_contracts,
    ).extract_inventory()
    mapper._inventory = foreign_inventory

    foreign_report = mapper.map_framework_phase_report()

    assert foreign_report is not None
    assert foreign_report.record_count == 0
    assert any(
        "outside the mapper's target project root" in item for item in foreign_report.limitations
    )

    scip_mapper = _framework_mapper(target_app, use_scip=True)
    scip_report = scip_mapper.map_framework_phase_report()
    assert scip_report is not None
    assert scip_report.snapshot_side == "target"
    assert scip_report.record_count == 0
    assert any("selected SCIP mapper" in item for item in scip_report.limitations)
    assert scip_mapper._mypy_analyzer is None


def test_public_mapper_reextracts_the_selected_factory_root(tmp_path: Path) -> None:
    app = tmp_path / "main.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "unused = FastAPI()\n"
        "@unused.on_event('startup')\n"
        "async def unused_startup() -> None: pass\n"
        "def create_app():\n"
        "    selected = FastAPI()\n"
        "    @selected.on_event('shutdown')\n"
        "    async def selected_shutdown() -> None: pass\n"
        "    return selected\n",
        encoding="utf-8",
    )
    mapper = _framework_mapper(app, app_entry="main:create_app")
    assert [item.handler.name for item in mapper.inventory.endpoints] == ["selected_shutdown"]
    mapper._mypy_analyzer = mapper.mypy_analyzer

    phase_report = mapper.map_framework_phase_report()

    assert phase_report is not None
    assert [item["callback"]["symbol"] for item in phase_report.records] == ["selected_shutdown"]
    assert phase_report.records[0]["phase"] == "shutdown"


def test_structured_output_adds_framework_report_only_when_selected(tmp_path: Path) -> None:
    app = _write_app(tmp_path)
    mapper = _framework_mapper(app)
    _ = mapper.inventory
    mapper._mypy_analyzer = mapper.mypy_analyzer
    phase_report = mapper.map_framework_phase_report()
    assert phase_report is not None
    default_report = AnalysisReport(app_path=str(tmp_path), diff_source="stdin", total_endpoints=0)
    selected_report = default_report.model_copy(update={"framework_phase_report": phase_report})

    default_json = json.loads(JsonFormatter().format(default_report))
    selected_json = json.loads(JsonFormatter().format(selected_report))
    default_yaml = YamlFormatter().format(default_report)
    selected_yaml = YamlFormatter().format(selected_report)

    assert "framework_phase_report" not in default_json
    assert "framework_phase_report" in selected_json
    assert default_json["schema_version"] == 4
    assert selected_json["schema_version"] == 5
    assert "framework_phase_report" not in default_yaml
    assert "framework_phase_report:" in selected_yaml
    assert "schema_version: 4" in default_yaml
    assert "schema_version: 5" in selected_yaml
