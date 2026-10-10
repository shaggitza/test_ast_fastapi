"""Unit tests for side-qualified Graphify inputs from secure inventories."""

from __future__ import annotations

from pathlib import Path

from fastapi_endpoint_detector.analyzer.graphify_input_adapter import (
    build_graphify_changed_ranges,
    build_graphify_endpoint_inputs,
)
from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile, DiffHunk
from fastapi_endpoint_detector.models.endpoint import (
    DependencyCallableKind,
    DependencyDeclarationKind,
    DependencyDeclarationScope,
    DependencyGraphLimitation,
    DependencyGraphStatus,
    DependencyResolutionStatus,
    DependencySourceSpan,
    Endpoint,
    EndpointDependencyGraph,
    EndpointDependencyOccurrence,
    EndpointMethod,
    HandlerInfo,
)


def _endpoint(
    root: Path,
    *,
    graph_status: DependencyGraphStatus = DependencyGraphStatus.ESTABLISHED,
    resolution_status: DependencyResolutionStatus = DependencyResolutionStatus.ESTABLISHED,
) -> Endpoint:
    limitation = (
        (
            DependencyGraphLimitation(
                code="conditional_di",
                source_path=Path("routes.py"),
                source_line=2,
                reason="Dependency registration is conditional",
            ),
        )
        if graph_status == DependencyGraphStatus.CONDITIONAL
        else ()
    )
    dependency_graph = EndpointDependencyGraph(
        status=graph_status,
        occurrences=(
            EndpointDependencyOccurrence(
                index_path=(0,),
                parent_path=(),
                depth=1,
                order=0,
                declaration_scope=DependencyDeclarationScope.PARAMETER,
                declaration_kind=DependencyDeclarationKind.DEPENDS,
                callable_kind=DependencyCallableKind.FUNCTION,
                resolution_status=resolution_status,
                display_name="db_provider",
                module="deps",
                qualname="db_provider",
                source_span=DependencySourceSpan(
                    file_path=Path("deps.py"), start_line=1, end_line=2
                ),
            ),
        ),
        limitations=limitation,
    )
    return Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="endpoint",
            module="routes",
            file_path=root / "routes.py",
            line_number=1,
            end_line_number=2,
        ),
        dependency_graph=dependency_graph,
    )


def test_changed_ranges_keep_removed_and_added_lines_on_their_own_sides() -> None:
    diff = DiffFile(
        path=Path("new/service.py"),
        source_path=Path("old/service.py"),
        change_type=ChangeType.RENAMED,
        hunks=[
            DiffHunk(
                source_start=4,
                source_length=4,
                target_start=8,
                target_length=4,
                removed_lines=[4, 6, 7],
                added_lines=[8, 9, 12],
            )
        ],
    )

    result = build_graphify_changed_ranges((diff,))

    assert [(item.file_path, item.start_line, item.end_line) for item in result.baseline] == [
        (Path("old/service.py"), 4, 4),
        (Path("old/service.py"), 6, 7),
    ]
    assert [(item.file_path, item.start_line, item.end_line) for item in result.target] == [
        (Path("new/service.py"), 8, 9),
        (Path("new/service.py"), 12, 12),
    ]
    assert result.limitations == ()


def test_line_less_file_change_is_reported_as_no_graphify_range() -> None:
    diff = DiffFile(path=Path("routes.py"), change_type=ChangeType.RENAMED)

    result = build_graphify_changed_ranges((diff,))

    assert result.baseline == ()
    assert result.target == ()
    assert "no line coordinates" in result.limitations[0]


def test_established_route_and_di_occurrence_keep_distinct_seed_identity(tmp_path: Path) -> None:
    endpoint = _endpoint(tmp_path)

    result = build_graphify_endpoint_inputs((endpoint,))

    assert [seed.binding_kind for seed in result.seeds] == ["handler", "dependency"]
    assert [seed.binding_identity for seed in result.seeds] == [
        "handler",
        "dependency:0",
    ]
    assert all(seed.endpoint_id == endpoint.identifier for seed in result.seeds)
    assert result.seeds[1].handler_name == "db_provider"
    assert result.seeds[1].file_path == Path("deps.py")
    assert result.seeds[1].confidence_ceiling is None
    assert result.limitations == ()


def test_conditional_di_occurrence_is_seeded_only_with_low_ceiling(tmp_path: Path) -> None:
    endpoint = _endpoint(
        tmp_path,
        graph_status=DependencyGraphStatus.CONDITIONAL,
        resolution_status=DependencyResolutionStatus.CONDITIONAL,
    )

    result = build_graphify_endpoint_inputs((endpoint,))

    dependency_seed = result.seeds[1]
    assert dependency_seed.binding_identity == "dependency:0"
    assert dependency_seed.confidence_ceiling == "LOW"
    assert any("conditional DI graph" in item for item in result.limitations)
