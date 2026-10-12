import platform
from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.evidence_graph import (
    EvidenceGraph,
    EvidenceProvenance,
    source_evidence_graph,
)
from fastapi_endpoint_detector.analyzer.source_inventory import (
    SourceFile,
    SourceInventory,
    build_source_inventory,
)
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
    assert graph.schema_version == 2
    assert (graph.edges[0].provenance.start_line, graph.edges[0].provenance.end_line) == (1, 1)
    assert graph.edges[0].provenance.source_path == "main.py"
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


def test_regular_module_and_rejected_symlink_alias_are_ambiguous(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.py").write_text("import dep\n", encoding="utf-8")
    (root / "dep.py").write_text("value = 'regular'\n", encoding="utf-8")
    external_package = tmp_path / "external-dep"
    external_package.mkdir()
    (external_package / "__init__.py").write_text("value = 'package'\n", encoding="utf-8")
    (root / "dep").symlink_to(external_package, target_is_directory=True)

    inventory = build_source_inventory(root, include_patterns=("**/*.py",))
    graph = source_evidence_graph(inventory)

    assert {item.relative_path for item in inventory.files} == {"main.py", "dep.py"}
    assert inventory.module_collisions == (("dep", ("dep", "dep.py")),)
    assert ("main.py", "dep") in inventory.unresolved_imports
    assert any(
        "ambiguous because module identity 'dep'" in item.lower() for item in inventory.limitations
    )
    assert not any(edge.target == "target:file:dep.py" for edge in graph.edges)
    assert any(node.attributes.get("module") == "dep" for node in graph.nodes)


def test_symlinked_root_package_initializer_records_identity_limitation(
    tmp_path: Path,
) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    external_init = tmp_path / "external_init.py"
    external_init.write_text("from pkg.helper import value\n", encoding="utf-8")
    (package / "__init__.py").symlink_to(external_init)
    (package / "main.py").write_text("import helper\n", encoding="utf-8")
    (package / "helper.py").write_text("value = 1\n", encoding="utf-8")

    inventory = build_source_inventory(package, include_patterns=("**/*.py",))
    graph = source_evidence_graph(inventory)

    limitation = (
        "Root package initializer __init__.py is a rejected symlink; package-prefix identity "
        "may differ from Python import resolution"
    )
    assert limitation in inventory.limitations
    assert limitation in graph.nodes[0].provenance.limitations
    assert {item.module for item in inventory.files} == {"main", "helper"}


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


def test_import_edges_preserve_each_source_statement_span(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "# heading\nimport lib\nfrom lib import helper\n", encoding="utf-8"
    )
    (tmp_path / "lib.py").write_text("def helper(): pass\n", encoding="utf-8")
    inventory = build_source_inventory(tmp_path)
    graph = source_evidence_graph(inventory, side="baseline")
    edges = [
        edge
        for edge in graph.edges
        if edge.source == "baseline:file:main.py" and edge.target == "baseline:file:lib.py"
    ]
    assert [(edge.provenance.start_line, edge.provenance.end_line) for edge in edges] == [
        (2, 2),
        (3, 3),
    ]
    assert all(edge.provenance.side == "baseline" for edge in edges)
    assert all(edge.provenance.source_path == "main.py" for edge in edges)
    assert all(edge.provenance.confidence == "low" for edge in edges)
    assert all(edge.provenance.engine == "python-ast" for edge in edges)
    assert all(edge.provenance.engine_version for edge in edges)
    assert all(
        "Import reachability does not establish execution" in edge.provenance.limitations
        for edge in edges
    )
    main = next(item for item in inventory.files if item.relative_path == "main.py")
    assert main.imports == ("lib", "lib.helper")


@pytest.mark.parametrize("prefix", ("", "label = 'é'; "))
def test_same_line_imports_keep_distinct_utf8_byte_columns(tmp_path: Path, prefix: str) -> None:
    source = prefix + "import lib; from lib import helper\n"
    (tmp_path / "main.py").write_text(source, encoding="utf-8")
    (tmp_path / "lib.py").write_text("def helper(): pass\n", encoding="utf-8")
    graph = source_evidence_graph(build_source_inventory(tmp_path))
    edges = [
        edge
        for edge in graph.edges
        if edge.source == "target:file:main.py" and edge.target == "target:file:lib.py"
    ]
    assert len(edges) == 2
    first_column = len(prefix.encode("utf-8"))
    second_column = first_column + len(b"import lib; ")
    expected = (
        (first_column, first_column + len(b"import lib"), b"import lib"),
        (second_column, second_column + len(b"from lib import helper"), b"from lib import helper"),
    )
    for edge, (start_column, end_column, spelling) in zip(edges, expected, strict=True):
        assert (edge.provenance.start_line, edge.provenance.end_line) == (1, 1)
        assert (edge.provenance.start_column, edge.provenance.end_column) == (
            start_column,
            end_column,
        )
        assert source.encode("utf-8")[start_column:end_column] == spelling


def test_multiline_import_retains_full_ast_span(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("from lib import (\n    helper,\n)\n", encoding="utf-8")
    (tmp_path / "lib.py").write_text("def helper(): pass\n", encoding="utf-8")
    graph = source_evidence_graph(build_source_inventory(tmp_path))
    edge = next(edge for edge in graph.edges if edge.source == "target:file:main.py")
    assert (
        edge.provenance.start_line,
        edge.provenance.start_column,
        edge.provenance.end_line,
        edge.provenance.end_column,
    ) == (1, 0, 3, 1)


@pytest.mark.parametrize(
    ("mode", "reason"),
    (
        ("no_follow", "follow_imports is disabled"),
        ("excluded", "excluded source"),
        ("depth", "maximum import depth"),
        ("collision", "is ambiguous"),
        ("symlink", "rejected symlink source"),
    ),
)
def test_unresolved_import_causes_preserve_statement_coordinates(
    tmp_path: Path, mode: str, reason: str
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "main.py").write_text("\nimport helper\nimport helper\n", encoding="utf-8")
    options = {"include_patterns": ("main.py",)}
    if mode == "symlink":
        outside = tmp_path / "outside.py"
        outside.write_text("value = 1\n", encoding="utf-8")
        (root / "helper.py").symlink_to(outside)
    else:
        (root / "helper.py").write_text("value = 1\n", encoding="utf-8")
    if mode == "no_follow":
        options["follow_imports"] = False
    elif mode == "excluded":
        options["exclude_patterns"] = ("helper.py",)
    elif mode == "depth":
        options["max_depth"] = 0
    elif mode == "collision":
        (root / "helper").mkdir()
        (root / "helper" / "__init__.py").write_text("", encoding="utf-8")
    inventory = build_source_inventory(root, **options)
    assert inventory.unresolved_imports == (("main.py", "helper"),)
    assert len(inventory.unresolved_import_occurrences) == 2
    graph = source_evidence_graph(inventory)
    edges = [edge for edge in graph.edges if edge.source == "target:file:main.py"]
    assert len(edges) == 2
    assert edges[0].target == edges[1].target
    assert all(edge.target.startswith("target:unresolved-import:") for edge in edges)
    assert [
        (
            edge.provenance.start_line,
            edge.provenance.start_column,
            edge.provenance.end_line,
            edge.provenance.end_column,
        )
        for edge in edges
    ] == [(2, 0, 2, 13), (3, 0, 3, 13)]
    assert all(any(reason in item for item in edge.provenance.limitations) for edge in edges)


def test_legacy_inventory_imports_keep_spanless_edges(tmp_path: Path) -> None:
    main = SourceFile(tmp_path / "main.py", "main.py", "main", "a" * 64, ("helper",))
    helper = SourceFile(tmp_path / "helper.py", "helper.py", "helper", "b" * 64, ())
    inventory = SourceInventory(tmp_path, (main, helper), (), (), True, 10)
    graph = source_evidence_graph(inventory)
    resolved = next(edge for edge in graph.edges if edge.target == "target:file:helper.py")
    assert resolved.provenance.start_line is resolved.provenance.end_line is None
    assert resolved.provenance.start_column is resolved.provenance.end_column is None

    unresolved = SourceInventory(tmp_path, (main,), (("main.py", "outside"),), (), True, 10)
    unresolved_graph = source_evidence_graph(unresolved)
    unresolved_edge = next(
        edge
        for edge in unresolved_graph.edges
        if edge.target.startswith("target:unresolved-import:")
    )
    assert unresolved_edge.provenance.start_line is unresolved_edge.provenance.end_line is None
    assert unresolved_edge.provenance.start_column is unresolved_edge.provenance.end_column is None


def test_v1_graph_inputs_remain_supported_without_v2_columns(tmp_path: Path) -> None:
    main = SourceFile(tmp_path / "main.py", "main.py", "main", "a" * 64, ())
    graph = source_evidence_graph(SourceInventory(tmp_path, (main,), (), (), True, 10))
    payload = graph.model_dump()
    payload["schema_version"] = 1
    provenance = payload["nodes"][0]["provenance"]
    provenance.pop("start_column")
    provenance.pop("end_column")
    provenance["start_line"] = 2
    provenance["end_line"] = 4
    legacy = EvidenceGraph.model_validate(payload)
    assert legacy.schema_version == 1
    assert legacy.nodes[0].provenance.start_column is None
    assert legacy.nodes[0].provenance.end_column is None
    assert (legacy.nodes[0].provenance.start_line, legacy.nodes[0].provenance.end_line) == (2, 4)
    provenance["start_column"] = 0
    provenance["end_column"] = 8
    with pytest.raises(ValueError, match="column spans require schema version 2"):
        EvidenceGraph.model_validate(payload)


@pytest.mark.parametrize(
    ("coordinates", "message"),
    (
        ({"start_line": 1, "end_line": 1, "start_column": 4}, "columns must be paired"),
        ({"start_line": 1, "end_line": 1, "end_column": 4}, "columns must be paired"),
        ({"start_column": 0, "end_column": 4}, "require both line endpoints"),
        ({"start_line": 1, "start_column": 0, "end_column": 4}, "require both line endpoints"),
        ({"end_line": 1, "start_column": 0, "end_column": 4}, "require both line endpoints"),
        (
            {"start_line": 1, "end_line": 1, "start_column": 4, "end_column": 3},
            "end must not precede its start",
        ),
        (
            {"start_line": 2, "end_line": 1, "start_column": 0, "end_column": 4},
            "end must not precede its start",
        ),
        (
            {"start_line": 1, "end_line": 1, "start_column": -1, "end_column": 4},
            "positions must be nonnegative",
        ),
        (
            {"start_line": 0, "end_line": 1, "start_column": 0, "end_column": 4},
            "positive lines",
        ),
    ),
)
def test_provenance_rejects_incomplete_or_invalid_column_spans(
    coordinates: dict[str, int], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        EvidenceProvenance(
            side="target",
            source_path="main.py",
            engine="python-ast",
            engine_version="test",
            strength="reference",
            confidence="low",
            **coordinates,
        )
