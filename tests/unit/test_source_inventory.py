from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.evidence_graph import source_evidence_graph
from fastapi_endpoint_detector.analyzer.source_inventory import build_source_inventory
from fastapi_endpoint_detector.config import Config


def test_source_inventory_follows_local_imports_with_scope_and_stable_hash(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("from lib import helper\n", encoding="utf-8")
    (tmp_path / "lib.py").write_text("def helper(): pass\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text("x = 1\n", encoding="utf-8")
    inventory = build_source_inventory(tmp_path, include_patterns=("**/*.py",))
    assert {item.relative_path for item in inventory.files} == {"lib.py", "main.py"}
    graph = source_evidence_graph(inventory)
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert graph.edges[0].kind == "imports"
    assert graph.edges[0].provenance.confidence == "low"
    assert any(
        "does not establish execution" in item for item in graph.edges[0].provenance.limitations
    )


def test_include_tests_and_follow_imports_are_consumed(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import helper\n", encoding="utf-8")
    (tmp_path / "helper.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "test_api.py").write_text("value = 2\n", encoding="utf-8")
    scoped = Config().source_inventory(tmp_path)
    assert {item.relative_path for item in scoped.files} == {"app.py", "helper.py"}
    no_follow = Config(
        parser={"include_patterns": ["app.py"], "follow_imports": False}
    ).source_inventory(tmp_path)
    assert {item.relative_path for item in no_follow.files} == {"app.py"}
    followed = Config(parser={"include_patterns": ["app.py"]}).source_inventory(tmp_path)
    assert {item.relative_path for item in followed.files} == {"app.py", "helper.py"}
    with_tests = Config(analysis={"include_test_endpoints": True}).source_inventory(tmp_path)
    assert "test_api.py" in {item.relative_path for item in with_tests.files}


def test_unsupported_mypy_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="mypy_config is not supported"):
        Config(integrations={"mypy_config": "mypy.ini"})
