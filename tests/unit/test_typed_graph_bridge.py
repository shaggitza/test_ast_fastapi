"""Production bridge checks against the analyzer's retained ordinary mypy build."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.analyzer.source_inventory import (
    SourceInventory,
    build_source_inventory,
)
from fastapi_endpoint_detector.analyzer.typed_graph_bridge import (
    TypedGraphBridgeError,
    build_shadow_graph,
    retained_typed_build,
)
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _endpoint(path: Path, module: str, *, name: str = "handler", line: int = 5) -> Endpoint:
    return Endpoint(
        path="/",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(name=name, module=module, file_path=path, line_number=line),
    )


def _source(tmp_path: Path) -> tuple[Path, SourceInventory, MypyAnalyzer]:
    app = tmp_path / "app.py"
    app.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "def helper() -> int: return 1\n"
        "@app.get('/')\n"
        "def handler() -> int: return helper()\n",
        encoding="utf-8",
    )
    decoy = tmp_path / "decoy.py"
    decoy.write_text("def handler() -> str: return 'decoy'\n", encoding="utf-8")
    inventory = build_source_inventory(tmp_path)
    analyzer = MypyAnalyzer(app, module_root=tmp_path, source_inventory=inventory)
    analyzer._ensure_mypy_built()
    return app, inventory, analyzer


def test_retained_ordinary_build_is_wrapped_with_exact_provenance(tmp_path: Path) -> None:
    app, inventory, analyzer = _source(tmp_path)
    typed, snapshots, config_fingerprint = retained_typed_build(analyzer, inventory)

    assert typed.result is analyzer._build_result
    assert typed.modules is analyzer._build_result.graph
    assert config_fingerprint
    assert snapshots["app"].decode().startswith("from fastapi")
    assert typed.report.mode == "same_ordinary_build_result"
    assert dict(typed.report.source_digests_after) == {
        record.module: record.sha256 for record in inventory.files
    }
    graph = build_shadow_graph(analyzer, inventory, [_endpoint(app, "app")])
    assert {binding.symbol for binding in graph.endpoint_bindings} == {"app.handler"}
    assert any(edge.caller == "app.handler" and edge.callee == "app.helper" for edge in graph.edges)


def test_handler_module_path_and_line_decoys_fail_closed(tmp_path: Path) -> None:
    app, inventory, analyzer = _source(tmp_path)
    for endpoint in (
        _endpoint(app, "decoy"),
        _endpoint(app, "app", line=3),
        _endpoint(tmp_path / "decoy.py", "app"),
    ):
        with pytest.raises(TypedGraphBridgeError):
            build_shadow_graph(analyzer, inventory, [endpoint])


def test_source_mutation_after_mypy_build_is_rejected(tmp_path: Path) -> None:
    app, inventory, analyzer = _source(tmp_path)
    app.write_text(app.read_text(encoding="utf-8") + "# changed after build\n", encoding="utf-8")

    with pytest.raises(TypedGraphBridgeError):
        retained_typed_build(analyzer, inventory)
