"""Synthetic mypy-to-contract integration checks for framework phases."""

import copy
import hashlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from mypy.nodes import AssignmentStmt, CallExpr, Decorator, FuncDef, NameExpr
from pydantic import ValidationError

from fastapi_endpoint_detector.analyzer import framework_phase_integration as phase_integration
from fastapi_endpoint_detector.analyzer.framework_phase_bridge import SourceIdentity
from fastapi_endpoint_detector.analyzer.framework_phase_graph import (
    adapt_framework_phases_to_graph,
)
from fastapi_endpoint_detector.analyzer.framework_phase_integration import (
    ConstructorLifespanEvidence,
    FrameworkPhaseIntegration,
    collect_framework_phase_evidence,
)
from fastapi_endpoint_detector.analyzer.framework_phase_report import phase_report_payload
from fastapi_endpoint_detector.analyzer.framework_phase_runtime import (
    ConstructorRegistrationEvidence,
)
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


def test_constructor_evidence_rejects_lookalike_fastapi_fullnames() -> None:
    callback = SourceIdentity(
        module="app",
        symbol="lifespan",
        file="app.py",
        line=1,
        column=0,
        source_sha256="sha256:" + "0" * 64,
    )
    fields = {
        "constructor_symbol": "fastapi.fake.FastAPI",
        "constructor_file": "fastapi/applications.py",
        "constructor_file_sha256": "sha256:" + "0" * 64,
        "provider_capture_sha256": "sha256:" + "1" * 64,
        "constructor_line": 1,
        "constructor_column": 0,
        "constructor_end_line": 1,
        "constructor_end_column": 10,
        "callback_symbol": "app.lifespan",
        "callback": callback,
    }
    with pytest.raises(ValidationError, match="exact typed constructor"):
        ConstructorLifespanEvidence(**fields)
    with pytest.raises(ValidationError, match="typed FastAPI"):
        ConstructorRegistrationEvidence(**fields)


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


def test_bounded_provider_source_read_rejects_oversized_input(tmp_path: Path) -> None:
    source = tmp_path / "large.py"
    source.write_bytes(b"12345")

    with pytest.raises(OSError, match="evidence read limit"):
        phase_integration._bounded_source_bytes(source, max_bytes=4)


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
    assert all("constructor_lifespan" not in item for item in payload.records)
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
    typed_build = _typed_build(tmp_path)
    report = collect_framework_phase_evidence(
        inventory,
        contracts,
        MypyAnalyzer(tmp_path),
        typed_build,
    )

    assert {record.phase.value for record in report.records} == {"startup", "shutdown"}
    startup = next(record for record in report.records if record.phase.value == "startup")
    shutdown = next(record for record in report.records if record.phase.value == "shutdown")
    assert startup.callback_range.value == "before_yield"
    assert shutdown.callback_range.value == "after_yield"
    assert startup.status == shutdown.status == "conditional", (
        startup.limitations,
        shutdown.limitations,
        startup.constructor_lifespan,
        shutdown.constructor_lifespan,
        startup.registration,
        shutdown.registration,
        [
            (item.surface.registration_line, item.surface.registration_column)
            for item in inventory.endpoints
            if item.surface
        ],
    )
    assert startup.constructor_lifespan is not None
    assert shutdown.constructor_lifespan is not None
    assert startup.constructor_lifespan.provider_capture_sha256.startswith("sha256:")
    assert startup.registration is not None and shutdown.registration is not None
    assert startup.registration_call_site is shutdown.registration_call_site is None
    assert startup.constructor_lifespan.constructor_symbol.startswith("fastapi.")
    assert startup.constructor_lifespan.callback_symbol == startup.typed_callback_symbol
    assert any("startup_work" in site.source_spelling for site in startup.body_call_sites)
    assert all("shutdown_work" not in site.source_spelling for site in startup.body_call_sites)
    assert any("shutdown_work" in site.source_spelling for site in shutdown.body_call_sites)
    manifest = phase_report_payload(report).runtime_manifest
    assert len(manifest["entries"]) == 2
    assert all("constructor_lifespan" in item for item in manifest["entries"])
    assert all(
        item["constructor_lifespan"]["provider_capture_sha256"].startswith("sha256:")
        for item in manifest["entries"]
    )


def test_constructor_scan_budget_exhaustion_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    typed_build = _typed_build(tmp_path)
    monkeypatch.setattr(phase_integration, "_CONSTRUCTOR_SCAN_MAX_NODES", 0)

    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )

    assert all(record.constructor_lifespan is None for record in report.records)
    assert all(record.status == "unavailable" for record in report.records)


def test_constructor_callback_requires_retained_node_identity(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    typed_build = _typed_build(tmp_path)
    tree = typed_build.modules["app"].tree
    assignment = next(item for item in tree.defs if isinstance(item, AssignmentStmt))
    call = assignment.rvalue
    assert isinstance(call, CallExpr)
    callback_index = call.arg_names.index("lifespan")
    callback = call.args[callback_index]
    assert isinstance(callback, NameExpr)
    original = callback.node.func if isinstance(callback.node, Decorator) else callback.node
    assert isinstance(original, FuncDef)
    callback.node = copy.copy(original)

    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )

    assert all(record.constructor_lifespan is None for record in report.records)


@pytest.mark.parametrize("bad_hash", (None, "0" * 40), ids=("missing", "incorrect"))
def test_framework_source_hash_mismatch_after_typed_build_fails_closed(
    tmp_path: Path, bad_hash: str | None
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    typed_build = _typed_build(tmp_path)
    state = typed_build.modules["fastapi.applications"]
    state.source_hash = bad_hash
    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )

    assert all(record.constructor_lifespan is None for record in report.records)
    assert all(record.status == "unavailable" for record in report.records)


def test_stale_external_fastapi_source_after_build_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    typed_build = _typed_build(tmp_path)
    framework_state = typed_build.modules["fastapi.applications"]
    stale_path = tmp_path / "stale_fastapi_applications.py"
    stale_path.write_bytes(Path(framework_state.tree.path).read_bytes() + b"\n# changed\n")
    framework_state.path = str(stale_path)
    framework_state.tree.path = str(stale_path)

    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )

    assert all(record.constructor_lifespan is None for record in report.records)
    assert all(record.status == "unavailable" for record in report.records)


@pytest.mark.parametrize(
    "registration",
    (
        "callback = lifespan\napp = FastAPI(lifespan=callback)\n",
        "app = FastAPI(**{'lifespan': lifespan})\n",
        "app = FastAPI(lifespan=lifespan)\nother = FastAPI(lifespan=lifespan)\n",
        "from fastapi import FastAPI as App\napp = App(lifespan=lifespan)\n",
        "def replacement(app):\n    yield\n"
        "lifespan = replacement\napp = FastAPI(lifespan=lifespan)\n",
        "FastAPI = type('FastAPI', (), {'__init__': lambda self, **kwargs: None})\n"
        "app = FastAPI(lifespan=lifespan)\n",
        "from callbacks import lifespan\napp = FastAPI(lifespan=lifespan)\n",
    ),
    ids=(
        "callback-alias",
        "expanded-keyword",
        "duplicate-constructor",
        "constructor-alias",
        "callback-rebound",
        "callee-rebound",
        "foreign-callback",
    ),
)
def test_constructor_lifespan_rejects_non_direct_or_ambiguous_bindings(
    tmp_path: Path, registration: str
) -> None:
    (tmp_path / "callbacks.py").write_text(
        "from contextlib import asynccontextmanager\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n",
        encoding="utf-8",
    )
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n" + registration,
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), _typed_build(tmp_path)
    )

    assert all(record.constructor_lifespan is None for record in report.records)


@pytest.mark.parametrize(
    "registration",
    ("with nullcontext():\n    app = FastAPI(lifespan=lifespan)\n",),
    ids=("with",),
)
def test_constructor_scan_finds_eager_statement_bodies(tmp_path: Path, registration: str) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager, nullcontext\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n" + registration,
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), _typed_build(tmp_path)
    )

    assert report.records
    assert all(record.constructor_lifespan is not None for record in report.records)
    assert all(record.status == "conditional" for record in report.records)
    surface = inventory.endpoints[0].surface
    assert surface is not None
    assert all(
        (evidence := record.constructor_lifespan) is not None
        and evidence.constructor_line == surface.registration_line
        and evidence.constructor_column == surface.registration_column
        and evidence.callback_symbol == record.typed_callback_symbol
        for record in report.records
    )


def test_constructor_scan_finds_walrus_constructor_selected_by_extractor(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "(app := FastAPI(lifespan=lifespan))\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    surface = inventory.endpoints[0].surface
    assert surface is not None
    typed_build = _typed_build(tmp_path)

    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )

    assert report.records
    for record in report.records:
        evidence = record.constructor_lifespan
        assert evidence is not None
        assert record.status == "conditional"
        assert evidence.constructor_line == surface.registration_line
        assert evidence.constructor_column == surface.registration_column
        assert evidence.callback_symbol == record.typed_callback_symbol


@pytest.mark.parametrize(
    "registration",
    (
        "(first := FastAPI(lifespan=lifespan))\n(second := FastAPI(lifespan=lifespan))\n",
        "def deferred():\n    (app := FastAPI(lifespan=lifespan))\n",
    ),
    ids=("repeated-walrus-constructors", "deferred-walrus-constructor"),
)
def test_constructor_scan_rejects_ambiguous_or_deferred_walrus_constructors(
    tmp_path: Path, registration: str
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "app = FastAPI(lifespan=lifespan)\n" + registration,
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), _typed_build(tmp_path)
    )

    assert report.records
    if registration.startswith("def deferred"):
        assert all(record.constructor_lifespan is not None for record in report.records)
        assert all(record.status == "conditional" for record in report.records)
    else:
        assert all(record.constructor_lifespan is None for record in report.records)


@pytest.mark.parametrize(
    "statement",
    (
        "try:\n    FastAPI()\nexcept RuntimeError:\n    pass\n",
        "for _item in ():\n    FastAPI()\n",
        "while False:\n    FastAPI()\n",
        "match 0:\n    case 0:\n        FastAPI()\n",
    ),
    ids=("try", "for", "while", "match"),
)
def test_constructor_scan_counts_nested_eager_constructors(tmp_path: Path, statement: str) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "app = FastAPI(lifespan=lifespan)\n" + statement,
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), _typed_build(tmp_path)
    )

    assert all(record.constructor_lifespan is None for record in report.records)


@pytest.mark.parametrize(
    "registration",
    (
        "def deferred():\n    app = FastAPI(lifespan=lifespan)\n",
        "class Deferred:\n    app = FastAPI(lifespan=lifespan)\n",
        "if flag:\n    app = FastAPI(lifespan=lifespan)\n"
        "else:\n    other = FastAPI(lifespan=lifespan)\n",
    ),
    ids=("function-body", "class-body", "ambiguous-branches"),
)
def test_constructor_scan_excludes_deferred_bodies_and_rejects_ambiguity(
    tmp_path: Path, registration: str
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "app = FastAPI(lifespan=lifespan)\n" + registration,
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), _typed_build(tmp_path)
    )

    if registration.startswith("if flag:"):
        assert all(record.constructor_lifespan is None for record in report.records)
    else:
        assert report.records
        assert all(record.constructor_lifespan is not None for record in report.records)


def test_constructor_scan_depth_budget_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager, nullcontext\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "with nullcontext():\n    with nullcontext():\n"
        "        app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    typed_build = _typed_build(tmp_path)
    monkeypatch.setattr(phase_integration, "_CONSTRUCTOR_SCAN_MAX_DEPTH", 1)

    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )

    assert all(record.constructor_lifespan is None for record in report.records)


def test_constructor_lifespan_rejects_caller_source_changed_after_typed_build(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    original = (
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "app = FastAPI(lifespan=lifespan)\n"
    )
    source.write_text(original, encoding="utf-8")
    inventory, contracts = _inventory(source)
    typed_build = _typed_build(tmp_path)
    source.write_text(original.replace("lifespan=lifespan", "lifespan=None"), encoding="utf-8")

    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), typed_build
    )

    assert all(record.constructor_lifespan is None for record in report.records)


def test_local_fastapi_module_shadow_cannot_prove_lifespan_constructor(
    tmp_path: Path,
) -> None:
    (tmp_path / "fastapi.py").write_text(
        "class FastAPI:\n"
        "    def __init__(self, *, lifespan=None):\n        self.lifespan = lifespan\n",
        encoding="utf-8",
    )
    source = tmp_path / "app.py"
    source.write_text(
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "@asynccontextmanager\nasync def lifespan(app):\n    yield\n"
        "app = FastAPI(lifespan=lifespan)\n",
        encoding="utf-8",
    )
    inventory, contracts = _inventory(source)
    report = collect_framework_phase_evidence(
        inventory, contracts, MypyAnalyzer(tmp_path), _typed_build(tmp_path)
    )

    assert all(record.constructor_lifespan is None for record in report.records)


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


@pytest.mark.parametrize(("suffix", "accepted"), ((".py", True), (".pyi", False)))
def test_only_executable_framework_sources_attest_runtime_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    accepted: bool,
) -> None:
    source_root = tmp_path / "project"
    module_path = tmp_path / "site-packages" / "fastapi" / f"applications{suffix}"
    module_path.parent.mkdir(parents=True)
    module_path.write_text("class FastAPI: pass\n", encoding="utf-8")
    distribution = SimpleNamespace(
        files=(Path(module_path.name),),
        locate_file=lambda _item: module_path,
    )
    monkeypatch.setattr(
        phase_integration.importlib.metadata, "distribution", lambda _name: distribution
    )
    typed_build = SimpleNamespace(
        modules={
            "fastapi.applications": SimpleNamespace(tree=SimpleNamespace(path=str(module_path)))
        }
    )
    site = SimpleNamespace(
        canonical_symbol="fastapi.applications.FastAPI.on_event",
        receiver_candidates=("fastapi.applications.FastAPI",),
    )

    actual = phase_integration._trusted_framework_source(site, typed_build, source_root)

    if accepted:
        assert actual == (
            module_path.resolve(),
            "sha256:" + hashlib.sha256(module_path.read_bytes()).hexdigest(),
        )
    else:
        assert actual is None
