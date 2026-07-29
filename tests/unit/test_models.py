"""
Unit tests for the Pydantic models.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.models.diff import (
    ChangeType,
    DiffFile,
    DiffHunk,
)
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
    EndpointDiscoveryCondition,
    EndpointDiscoveryStatus,
    EndpointInventory,
    EndpointMethod,
    HandlerInfo,
    InventoryStatus,
)
from fastapi_endpoint_detector.models.report import (
    AffectedEndpoint,
    AnalysisReport,
    ConfidenceLevel,
)


class TestHandlerInfo:
    """Tests for HandlerInfo model."""

    def test_create_handler_info(self) -> None:
        """Test creating a HandlerInfo."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )

        assert handler.name == "get_users"
        assert handler.module == "routers.users"
        assert handler.line_number == 10
        assert handler.end_line_number is None

    def test_handler_info_frozen(self) -> None:
        """Test that HandlerInfo is frozen (immutable)."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )

        with pytest.raises(ValidationError):
            handler.name = "new_name"


class TestEndpoint:
    """Tests for Endpoint model."""

    def test_create_endpoint(self) -> None:
        """Test creating an Endpoint."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        assert endpoint.path == "/api/users"
        assert EndpointMethod.GET in endpoint.methods

    def test_dependency_graph_none_and_established_empty_are_distinct(self) -> None:
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        legacy = Endpoint(path="/legacy", methods=[EndpointMethod.GET], handler=handler)
        collected = legacy.model_copy(
            update={
                "dependency_graph": EndpointDependencyGraph(
                    status=DependencyGraphStatus.ESTABLISHED
                )
            }
        )

        assert legacy.dependency_graph is None
        assert collected.dependency_graph is not None
        assert collected.dependency_graph.occurrences == ()
        with pytest.raises(ValidationError):
            collected.dependency_graph.status = DependencyGraphStatus.CONDITIONAL

    def test_dependency_graph_uncertainty_requires_graph_scoped_limitation(self) -> None:
        limitation = DependencyGraphLimitation(
            code="shape_unavailable",
            source_path=Path("/app/main.py"),
            source_line=4,
            reason="FastAPI dependant shape changed",
        )
        graph = EndpointDependencyGraph(
            status=DependencyGraphStatus.CONDITIONAL,
            limitations=(limitation,),
        )

        assert graph.limitations == (limitation,)
        with pytest.raises(ValueError, match="conditional/unavailable require"):
            EndpointDependencyGraph(status=DependencyGraphStatus.CONDITIONAL)

    def test_dependency_graph_rejects_malformed_tree_and_strength_payloads(self) -> None:
        def occurrence(path: tuple[int, ...], order: int) -> EndpointDependencyOccurrence:
            return EndpointDependencyOccurrence(
                index_path=path,
                parent_path=path[:-1],
                depth=len(path),
                order=order,
                declaration_scope=DependencyDeclarationScope.NESTED,
                declaration_kind=DependencyDeclarationKind.DEPENDS_OR_SECURITY,
                callable_kind=DependencyCallableKind.FUNCTION,
                resolution_status=DependencyResolutionStatus.ESTABLISHED,
                display_name="dependency",
                module="main",
                qualname="dependency",
                source_span=DependencySourceSpan(
                    file_path=Path("/app/main.py"), start_line=1, end_line=2
                ),
            )

        malformed = [
            (occurrence((-1,), 0), "bounded nonnegative"),
            (occurrence((0, 0), 0), "parent must exist earlier"),
            (occurrence((1,), 0), "indexes must be contiguous"),
        ]
        for item, message in malformed:
            with pytest.raises(ValueError, match=message):
                EndpointDependencyGraph(
                    status=DependencyGraphStatus.ESTABLISHED,
                    occurrences=(item,),
                )

        with pytest.raises(ValueError, match="depth-first preorder"):
            EndpointDependencyGraph(
                status=DependencyGraphStatus.ESTABLISHED,
                occurrences=(
                    occurrence((0,), 0),
                    occurrence((1,), 1),
                    occurrence((0, 0), 2),
                ),
            )

        uncertain = occurrence((0,), 0).model_copy(
            update={"resolution_status": DependencyResolutionStatus.CONDITIONAL}
        )
        with pytest.raises(ValueError, match="only established occurrences"):
            EndpointDependencyGraph(
                status=DependencyGraphStatus.ESTABLISHED,
                occurrences=(uncertain,),
            )

        orphan_payload = {
            "status": "established",
            "occurrences": [occurrence((0, 0), 0).model_dump(mode="json")],
        }
        with pytest.raises(ValueError, match="parent must exist earlier"):
            EndpointDependencyGraph.model_validate_json(json.dumps(orphan_payload))

    def test_endpoint_identifier(self) -> None:
        """Test the endpoint identifier property."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET, EndpointMethod.POST],
            handler=handler,
        )

        # Methods should be sorted in identifier
        assert endpoint.identifier == "GET,POST /api/users"


class TestEndpointInventory:
    """Tests for whole-inventory route uncertainty invariants."""

    def test_route_conditions_default_is_backward_compatible(self) -> None:
        assert EndpointInventory().route_conditions == ()

    def test_route_conditions_require_conditioned_native_endpoints(self) -> None:
        condition = EndpointDiscoveryCondition(
            source_path=Path("/app/main.py"),
            source_line=9,
            reason="startup may mutate routes",
        )
        endpoint = Endpoint(
            path="/known",
            methods=[EndpointMethod.GET],
            handler=HandlerInfo(
                name="known",
                module="main",
                file_path=Path("/app/main.py"),
                line_number=3,
            ),
        )

        with pytest.raises(ValueError, match="native endpoints must be conditional"):
            EndpointInventory(
                endpoints=[endpoint],
                status=InventoryStatus.CONDITIONAL,
                limitations=(condition,),
                route_conditions=(condition,),
            )

        conditioned = endpoint.model_copy(
            update={
                "discovery_status": EndpointDiscoveryStatus.CONDITIONAL,
                "discovery_conditions": (condition,),
            }
        )
        inventory = EndpointInventory(
            endpoints=[conditioned],
            status=InventoryStatus.CONDITIONAL,
            limitations=(condition,),
            route_conditions=(condition,),
        )
        assert inventory.endpoints == [conditioned]


class TestDiffHunk:
    """Tests for DiffHunk model."""

    def test_create_hunk(self) -> None:
        """Test creating a DiffHunk."""
        hunk = DiffHunk(
            source_start=10,
            source_length=5,
            target_start=10,
            target_length=8,
            added_lines=[13, 14, 15],
            removed_lines=[],
        )

        assert hunk.source_start == 10
        assert hunk.target_length == 8
        assert len(hunk.added_lines) == 3


class TestDiffFile:
    """Tests for DiffFile model."""

    def test_is_python_file(self) -> None:
        """Test the is_python_file property."""
        py_file = DiffFile(
            path=Path("services/user_service.py"),
            change_type=ChangeType.MODIFIED,
        )
        js_file = DiffFile(
            path=Path("frontend/app.js"),
            change_type=ChangeType.MODIFIED,
        )

        assert py_file.is_python_file is True
        assert js_file.is_python_file is False

    def test_get_affected_line_ranges(self) -> None:
        """Test getting affected line ranges."""
        hunk1 = DiffHunk(
            source_start=10,
            source_length=5,
            target_start=10,
            target_length=8,
            added_lines=[13, 14, 15],
            removed_lines=[],
        )
        hunk2 = DiffHunk(
            source_start=30,
            source_length=3,
            target_start=33,
            target_length=5,
            added_lines=[35, 36],
            removed_lines=[],
        )
        diff_file = DiffFile(
            path=Path("services/user_service.py"),
            change_type=ChangeType.MODIFIED,
            hunks=[hunk1, hunk2],
        )

        ranges = diff_file.get_affected_line_ranges()
        assert len(ranges) == 2
        assert ranges[0] == (10, 18)  # target_start + target_length
        assert ranges[1] == (33, 38)


class TestAnalysisReport:
    """Tests for AnalysisReport model."""

    def test_inventory_strength_is_backward_compatible(self) -> None:
        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=0,
        )

        assert report.inventory_status is None
        assert report.inventory_limitations == ()

    def test_inventory_strength_requires_consistent_limitations(self) -> None:
        limitation = EndpointDiscoveryCondition(
            source_path=Path("/app/main.py"),
            source_line=2,
            reason="module could not be parsed",
        )

        with pytest.raises(ValidationError, match="unset inventory status forbids"):
            AnalysisReport(
                app_path="/app",
                diff_source="test.diff",
                total_endpoints=0,
                inventory_limitations=(limitation,),
            )
        with pytest.raises(ValidationError, match="conditional/unavailable require"):
            AnalysisReport(
                app_path="/app",
                diff_source="test.diff",
                total_endpoints=0,
                inventory_status=InventoryStatus.CONDITIONAL,
            )
        with pytest.raises(ValidationError, match="established inventory forbids"):
            AnalysisReport(
                app_path="/app",
                diff_source="test.diff",
                total_endpoints=0,
                inventory_status=InventoryStatus.ESTABLISHED,
                inventory_limitations=(limitation,),
            )

        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=0,
            inventory_status=InventoryStatus.UNAVAILABLE,
            inventory_limitations=(limitation,),
        )
        assert report.inventory_limitations == (limitation,)

    def test_affected_count(self) -> None:
        """Test the affected_count property."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.HIGH,
            reason="Direct change",
            dependency_chain=["users.py"],
            changed_files=["users.py"],
        )

        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=10,
            affected_endpoints=[affected],
        )

        assert report.affected_count == 1
        assert report.high_confidence_count == 1

    def test_get_endpoints_by_confidence(self) -> None:
        """Test filtering endpoints by confidence."""
        handler = HandlerInfo(
            name="get_users",
            module="routers.users",
            file_path=Path("/app/routers/users.py"),
            line_number=10,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        high_affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.HIGH,
            reason="Direct change",
            dependency_chain=[],
            changed_files=[],
        )
        low_affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.LOW,
            reason="Transitive",
            dependency_chain=[],
            changed_files=[],
        )

        report = AnalysisReport(
            app_path="/app",
            diff_source="test.diff",
            total_endpoints=10,
            affected_endpoints=[high_affected, low_affected],
        )

        high_list = report.get_endpoints_by_confidence(ConfidenceLevel.HIGH)
        assert len(high_list) == 1

        low_list = report.get_endpoints_by_confidence(ConfidenceLevel.LOW)
        assert len(low_list) == 1
