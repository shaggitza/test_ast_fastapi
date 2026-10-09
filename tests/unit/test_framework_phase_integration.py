"""Synthetic mypy-to-contract integration checks for framework phases."""

import hashlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from fastapi_endpoint_detector.analyzer.framework_phase_graph import (
    adapt_framework_phases_to_graph,
)
from fastapi_endpoint_detector.analyzer.framework_phase_integration import (
    FrameworkPhaseIntegration,
    collect_framework_phase_evidence,
)
from fastapi_endpoint_detector.analyzer.framework_phase_report import phase_report_payload
from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.mypy_incremental import (
    BuildConfig,
    MypyIncrementalProvider,
    TypedBuild,
)
from fastapi_endpoint_detector.analyzer.typed_reverse_graph import (
    TypedReverseGraph,
    build_typed_reverse_graph,
)
from fastapi_endpoint_detector.models.endpoint import EndpointInventory
from fastapi_endpoint_detector.models.surface_contract import (
    LoadedSurfaceContracts,
    load_surface_preset,
)
from fastapi_endpoint_detector.parser.custom_surface_extractor import CustomSurfaceExtractor


def _inventory(source: Path) -> tuple[EndpointInventory, LoadedSurfaceContracts]:
    contracts = load_surface_preset("framework-v1")
    return CustomSurfaceExtractor(source, contracts).extract_inventory(), contracts


def _typed_build(root: Path) -> TypedBuild:
    inventory = {path.stem: str(path) for path in root.glob("*.py")}
    return MypyIncrementalProvider(BuildConfig(root)).build(inventory)


def _typed_graph(source: Path, typed_build: TypedBuild) -> TypedReverseGraph:
    return build_typed_reverse_graph(
        SimpleNamespace(
            root=source.parent,
            files=(
                SimpleNamespace(
                    module=source.stem,
                    path=source,
                    relative_path=source.name,
                    sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                ),
            ),
        ),
        typed_build,
        (),
        config_fingerprint="private-fixture-config",
    )


def _assert_graph_rejects_altered_callback_span(
    source: Path,
    typed_build: TypedBuild,
    report: FrameworkPhaseIntegration,
    callback_module: str,
    callback_symbol: str,
) -> None:
    graph = _typed_graph(source, typed_build)
    callback_symbol_node = next(
        symbol
        for symbol in graph.symbols
        if symbol.module == callback_module and symbol.fullname == callback_symbol
    )
    assert callback_symbol_node.span is not None
    altered_span = replace(
        callback_symbol_node.span,
        end_column=callback_symbol_node.span.end_column + 1,
    )
    altered_symbol = replace(callback_symbol_node, span=altered_span)
    altered_graph = replace(
        graph,
        symbols=tuple(
            altered_symbol if symbol is callback_symbol_node else symbol for symbol in graph.symbols
        ),
    )
    assert adapt_framework_phases_to_graph(report, altered_graph).bindings == ()


def test_typed_on_event_surfaces_join_physical_exact_registration_sites(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "async def late() -> dict[str, bool]: return {'ready': True}\n"
        "@app.on_event('startup')\n"
        "def start() -> None:\n"
        "    print('started')\n"
        "    app.add_api_route('/late', late, methods=['POST'])\n"
        "@app.on_event('shutdown')\n"
        "def stop() -> None:\n"
        "    print('stopped')\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    typed_build = _typed_build(tmp_path)
    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )

    assert len(report.records) == 2
    by_phase = {record.phase.value: record for record in report.records}
    startup, shutdown = by_phase["startup"], by_phase["shutdown"]
    assert startup.status == shutdown.status == "conditional", (
        startup.limitations,
        shutdown.limitations,
    )
    assert startup.callback_range.value == shutdown.callback_range.value == "full"
    assert startup.registration is not None and shutdown.registration is not None
    assert startup.typed_framework_symbol == "fastapi.applications.FastAPI.on_event"
    assert shutdown.typed_framework_symbol == "fastapi.applications.FastAPI.on_event"
    assert startup.registration.line != shutdown.registration.line
    assert any("print" in site.source_spelling for site in startup.body_call_sites)
    assert len(report.lifecycle_conditional_surfaces) == 1
    late_surface = report.lifecycle_conditional_surfaces[0]
    assert late_surface.surface_id == "/late"
    assert late_surface.lifecycle_surface_id == "event:startup"
    assert "only if startup lifecycle execution succeeds" in late_surface.condition
    activated = next(item for item in inventory.endpoints if item.activation is not None)
    assert activated.activation is not None
    forged_activation = activated.activation.model_copy(
        update={"activation_line": activated.activation.activation_line + 1}
    )
    forged_activation_endpoint = activated.model_copy(update={"activation": forged_activation})
    activation_inventory = inventory.model_copy(
        update={
            "endpoints": [
                forged_activation_endpoint if item is activated else item
                for item in inventory.endpoints
            ]
        }
    )
    activation_report = collect_framework_phase_evidence(
        activation_inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )
    assert activation_report.lifecycle_conditional_surfaces == ()
    assert any(
        "lifecycle activation is not present" in item for item in activation_report.limitations
    )
    payload = phase_report_payload(report)
    assert payload.conditional_count == 2
    first = startup
    callback = first.callback
    graph = _typed_graph(source, typed_build)
    adapted = adapt_framework_phases_to_graph(report, graph)
    assert {item.phase.value for item in adapted.bindings} == {"startup", "shutdown"}

    original = inventory.endpoints[0]
    assert original.surface is not None
    altered_surface = original.surface.model_copy(update={"conditions": ("caller asserted",)})
    altered_endpoint = original.model_copy(update={"surface": altered_surface})
    forged_inventory = inventory.model_copy(
        update={"endpoints": [altered_endpoint, *inventory.endpoints[1:]]}
    )
    forged_report = collect_framework_phase_evidence(
        forged_inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )
    assert len(forged_report.records) == 1
    assert forged_report.records[0].phase.value != altered_surface.resource
    assert any("fresh canonical source extraction" in item for item in forged_report.limitations)

    startup_report = report.model_copy(update={"records": (startup,)})
    _assert_graph_rejects_altered_callback_span(
        source,
        typed_build,
        startup_report,
        callback.module,
        f"{callback.module}.{callback.symbol}",
    )


def test_lifespan_phase_slices_stay_separate_when_constructor_registration_unbound(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "def startup_work() -> None: pass\n"
        "def shutdown_work() -> None: pass\n"
        "@asynccontextmanager\n"
        "async def lifespan(app):\n"
        "    startup_work()\n"
        "    yield\n"
        "    shutdown_work()\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    report = collect_framework_phase_evidence(
        inventory,
        contracts,
        MypyAnalyzer(tmp_path),
        _typed_build(tmp_path),
    )

    assert {record.phase.value for record in report.records} == {"startup", "shutdown"}
    startup = next(record for record in report.records if record.phase.value == "startup")
    shutdown = next(record for record in report.records if record.phase.value == "shutdown")
    assert startup.callback_range.value == "before_yield"
    assert shutdown.callback_range.value == "after_yield"
    assert startup.status == shutdown.status == "unavailable"
    assert startup.registration is shutdown.registration is None
    assert any("startup_work" in site.source_spelling for site in startup.body_call_sites)
    assert all("shutdown_work" not in site.source_spelling for site in startup.body_call_sites)
    assert any("shutdown_work" in site.source_spelling for site in shutdown.body_call_sites)


def test_local_fastapi_shadow_does_not_produce_selected_framework_evidence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "class FastAPI:\n"
        "    def on_event(self, event):\n"
        "        def register(function): return function\n"
        "        return register\n"
        "app = FastAPI()\n"
        "@app.on_event('startup')\n"
        "def start() -> None: pass\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    assert inventory.endpoints == []
    report = collect_framework_phase_evidence(
        inventory,
        contracts,
        MypyAnalyzer(tmp_path),
        None,
    )
    assert report.records == ()


def test_local_module_shadow_with_framework_fullname_is_rejected_by_distribution_provenance(
    tmp_path: Path,
) -> None:
    (tmp_path / "fastapi.py").write_text(
        "class FastAPI:\n"
        "    def on_event(self, event):\n"
        "        def register(function): return function\n"
        "        return register\n",
        encoding="utf-8",
    )
    source = tmp_path / "app.py"
    source.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.on_event('startup')\n"
        "def start() -> None: pass\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    assert inventory.endpoints
    report = collect_framework_phase_evidence(
        inventory,
        contracts,
        MypyAnalyzer(tmp_path),
        _typed_build(tmp_path),
    )

    assert len(report.records) == 1
    assert report.records[0].status == "unavailable"
    assert report.records[0].registration is None
    assert report.records[0].framework_declaration_sha256 is None
