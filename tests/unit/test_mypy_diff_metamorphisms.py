"""Side-aware change mapping regressions that do not invoke mypy."""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.change_mapper import ChangeMapper
from fastapi_endpoint_detector.analyzer.mypy_analyzer import CallFrame, EndpointDependencies
from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile, DiffHunk
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


def _fixture(
    tmp_path: Path, *, ranges: list[tuple[str, int, int]]
) -> tuple[ChangeMapper, Endpoint]:
    source = tmp_path / "service.py"
    source.write_text("\n".join(f"line_{n} = {n}" for n in range(1, 31)) + "\n")
    endpoint = Endpoint(
        path="/items",
        methods=[EndpointMethod.GET],
        handler=HandlerInfo(
            name="handler", module="main", file_path=tmp_path / "main.py", line_number=1
        ),
    )
    deps = EndpointDependencies(
        endpoint_id=endpoint.identifier,
        methods=["GET"], path="/items", source_root=str(tmp_path),
        project_files={str(source)},
    )
    for name, start, end in ranges:
        deps.add_symbol_reference(str(source), name, start, end)
    deps.add_call_stack(str(source), [CallFrame(str(source), 3, "work")])

    class Analyzer:
        def get_endpoint_dependencies(self, _endpoint: Endpoint) -> EndpointDependencies:
            return deps

    mapper = ChangeMapper(tmp_path)
    mapper._mypy_analyzer = Analyzer()  # type: ignore[assignment]
    return mapper, endpoint


@pytest.mark.parametrize(
    ("changed", "expected"),
    [
        ({5}, True),       # changed definition body
        ({6}, True),       # deleted old-side line
        ({12}, False),     # unrelated definition
        ({20}, False),     # unrelated same-name control
    ],
)
def test_reachable_and_unrelated_lines_are_distinguished(
    tmp_path: Path, changed: set[int], expected: bool
) -> None:
    mapper, endpoint = _fixture(tmp_path, ranges=[("pkg.service.work", 3, 8)])
    diff = DiffFile(path=Path("service.py"), change_type=ChangeType.MODIFIED)
    assert (
        mapper._check_mypy_dependency(endpoint, diff, sorted(changed), []) is not None
    ) is expected


def test_deletion_and_replacement_use_baseline_coordinates(tmp_path: Path) -> None:
    mapper, endpoint = _fixture(tmp_path, ranges=[("pkg.service.work", 4, 7)])
    diff = DiffFile(
        path=Path("service.py"), change_type=ChangeType.MODIFIED,
        hunks=[DiffHunk(source_start=5, source_length=1, target_start=5, target_length=1,
                        added_lines=[5], removed_lines=[5])],
    )
    assert mapper._check_mypy_dependency(endpoint, diff, [5], []) is not None
    assert mapper._check_mypy_dependency(endpoint, diff, [], [5]) is not None


def test_nested_range_is_reported_instead_of_enclosing_definition(tmp_path: Path) -> None:
    mapper, endpoint = _fixture(
        tmp_path, ranges=[("pkg.service", 1, 20), ("pkg.service.outer", 3, 15),
                          ("pkg.service.outer.inner", 8, 10)],
    )
    diff = DiffFile(path=Path("service.py"), change_type=ChangeType.MODIFIED)
    result = mapper._check_mypy_dependency(endpoint, diff, [9], [])
    assert result is not None
    assert any(frame.function_name == "pkg.service.outer.inner" for frame in result.call_stacks[0])


def test_pure_rename_has_no_changed_line_evidence(tmp_path: Path) -> None:
    mapper, endpoint = _fixture(tmp_path, ranges=[("pkg.service.work", 3, 8)])
    diff = DiffFile(path=Path("new/service.py"), source_path=Path("service.py"),
                    change_type=ChangeType.RENAMED)
    assert mapper._check_mypy_dependency(endpoint, diff, [], []) is None


def test_moved_target_path_resolves_target_dependency_only(tmp_path: Path) -> None:
    mapper, endpoint = _fixture(tmp_path, ranges=[("pkg.service.work", 3, 8)])
    moved = DiffFile(path=Path("new/service.py"), source_path=Path("old/service.py"),
                     change_type=ChangeType.RENAMED)
    # Current-tree evidence is queried by the target path. Without an explicit
    # alias in the dependency inventory, the old path cannot accidentally match.
    assert mapper._check_mypy_dependency(endpoint, moved, [5], []) is None
