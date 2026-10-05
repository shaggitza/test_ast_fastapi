import platform
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
    assert graph.edges[0].provenance.engine_version == (
        f"{platform.python_implementation()} {platform.python_version()}"
    )
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
    assert any("follow_imports is disabled" in item for item in no_follow.limitations)
    followed = Config(parser={"include_patterns": ["app.py"]}).source_inventory(tmp_path)
    assert {item.relative_path for item in followed.files} == {"app.py", "helper.py"}
    with_tests = Config(analysis={"include_test_endpoints": True}).source_inventory(tmp_path)
    assert "test_api.py" in {item.relative_path for item in with_tests.files}


def test_unsupported_mypy_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="mypy_config is not supported"):
        Config(integrations={"mypy_config": "mypy.ini"})


def test_inventory_rejects_symlink_escapes_and_symlink_aliases(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n", encoding="utf-8")
    (root / "app.py").write_text("import outside\nimport alias\n", encoding="utf-8")
    (root / "outside.py").symlink_to(outside)
    (root / "alias.py").symlink_to(root / "app.py")

    inventory = build_source_inventory(root, include_patterns=("**/*.py",))

    assert {item.relative_path for item in inventory.files} == {"app.py"}
    assert all(item.path.resolve().is_relative_to(root.resolve()) for item in inventory.files)
    assert set(inventory.unresolved_imports) >= {
        ("app.py", "outside"),
        ("app.py", "alias"),
    }
    assert any("rejected symlink source outside.py" in item for item in inventory.limitations)
    graph = source_evidence_graph(inventory)
    unresolved_nodes = [
        node for node in graph.nodes if node.attributes.get("resolution") == "unresolved"
    ]
    assert {node.attributes["module"] for node in unresolved_nodes} >= {"outside", "alias"}
    assert all(node.provenance.confidence == "low" for node in unresolved_nodes)
    assert all(edge.provenance.confidence == "low" for edge in graph.edges)


def test_source_inventory_rejects_symlink_root_and_file(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "main.py"
    source.write_text("value = 1\n", encoding="utf-8")
    root_alias = tmp_path / "project-alias"
    root_alias.symlink_to(project, target_is_directory=True)
    file_alias = project / "main-alias.py"
    file_alias.symlink_to(source)

    with pytest.raises(ValueError, match="must not use symlink paths"):
        build_source_inventory(root_alias)
    with pytest.raises(ValueError, match="must not use symlink paths"):
        build_source_inventory(file_alias)


def test_out_of_root_symlink_package_import_is_reported_without_traversal(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside_package = tmp_path / "outside_package"
    outside_package.mkdir()
    (outside_package / "__init__.py").write_text("", encoding="utf-8")
    (outside_package / "routes.py").write_text("def route(): pass\n", encoding="utf-8")
    (root / "app.py").write_text("from vendor.routes import route\n", encoding="utf-8")
    (root / "vendor").symlink_to(outside_package, target_is_directory=True)

    inventory = build_source_inventory(root, include_patterns=("**/*.py",))

    assert {item.relative_path for item in inventory.files} == {"app.py"}
    assert ("app.py", "vendor.routes") in inventory.unresolved_imports
    assert any("rejected symlink source vendor" in item for item in inventory.limitations)


def test_package_root_keeps_package_prefix_for_absolute_imports(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("from pkg.helper import value\n", encoding="utf-8")
    (package / "helper.py").write_text("value = 1\n", encoding="utf-8")

    inventory = build_source_inventory(package, include_patterns=("__init__.py",))

    assert {item.module for item in inventory.files} == {"pkg", "pkg.helper"}


def test_module_identity_collision_is_unresolved_not_arbitrarily_selected(
    tmp_path: Path,
) -> None:
    (tmp_path / "main.py").write_text("import ambiguous\n", encoding="utf-8")
    (tmp_path / "ambiguous.py").write_text("source = 'module'\n", encoding="utf-8")
    package = tmp_path / "ambiguous"
    package.mkdir()
    (package / "__init__.py").write_text("source = 'package'\n", encoding="utf-8")

    inventory = build_source_inventory(tmp_path, include_patterns=("**/*.py",))
    graph = source_evidence_graph(inventory)

    assert inventory.module_collisions == (
        ("ambiguous", ("ambiguous.py", "ambiguous/__init__.py")),
    )
    assert ("main.py", "ambiguous") in inventory.unresolved_imports
    assert any("Module identity 'ambiguous' collides" in item for item in inventory.limitations)
    assert not any(
        edge.source == "target:file:main.py"
        and edge.target in {"target:file:ambiguous.py", "target:file:ambiguous/__init__.py"}
        for edge in graph.edges
    )
    unresolved_node_ids = {
        node.id for node in graph.nodes if node.attributes.get("resolution") == "unresolved"
    }
    assert any(
        edge.source == "target:file:main.py" and edge.target in unresolved_node_ids
        for edge in graph.edges
    )


def test_parse_failure_is_retained_as_incomplete_inventory_evidence(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("import broken\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    inventory = build_source_inventory(
        tmp_path, include_patterns=("main.py", "broken.py"), follow_imports=False
    )
    graph = source_evidence_graph(inventory)

    assert {item.relative_path for item in inventory.files} == {"main.py", "broken.py"}
    assert all(item.sha256 for item in inventory.files)
    assert any("broken.py could not be parsed" in item for item in inventory.limitations)
    assert any(
        "broken.py could not be parsed" in item for item in graph.nodes[0].provenance.limitations
    )
    assert all(node.provenance.confidence == "low" for node in graph.nodes)
    assert graph.edges
    assert all(edge.provenance.confidence == "low" for edge in graph.edges)


def test_source_read_failure_is_not_reported_as_complete_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "unreadable.py"
    source.write_text("value = 1\n", encoding="utf-8")
    original_read_bytes = Path.read_bytes

    def fail_read_bytes(path: Path) -> bytes:
        if path == source:
            raise OSError("simulated unreadable source")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)

    inventory = build_source_inventory(tmp_path, include_patterns=("unreadable.py",))

    assert inventory.files[0].sha256 == ""
    assert any("unreadable.py could not be read" in item for item in inventory.limitations)


def test_import_into_excluded_source_is_explicitly_unresolved(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("from tests.test_app import helper\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (tests / "test_app.py").write_text("def helper(): pass\n", encoding="utf-8")

    inventory = build_source_inventory(tmp_path, include_patterns=("app.py",))

    assert set(inventory.unresolved_imports) >= {
        ("app.py", "tests.test_app"),
        ("app.py", "tests.test_app.helper"),
    }
    assert any(
        "resolves to excluded source tests/test_app.py" in item for item in inventory.limitations
    )


def test_import_depth_cap_is_explicitly_unresolved(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import first\n", encoding="utf-8")
    (tmp_path / "first.py").write_text("import second\n", encoding="utf-8")
    (tmp_path / "second.py").write_text("value = 1\n", encoding="utf-8")

    inventory = build_source_inventory(
        tmp_path,
        include_patterns=("app.py",),
        max_depth=1,
    )

    assert {item.relative_path for item in inventory.files} == {"app.py", "first.py"}
    assert inventory.unresolved_imports == (("first.py", "second"),)
    assert any("maximum import depth 1 was reached" in item for item in inventory.limitations)
