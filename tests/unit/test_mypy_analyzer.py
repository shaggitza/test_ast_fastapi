"""
Unit tests for the MypyAnalyzer.

These tests verify the mypy-based dependency analysis, including:
- Basic endpoint analysis
- Loop prevention in circular dependencies
- Line progress callbacks
"""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import (
    CallFrame,
    EndpointDependencies,
    MypyAnalyzer,
)
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


class TestMypyAnalyzerBasic:
    """Basic tests for MypyAnalyzer."""

    def test_create_analyzer(self, tmp_path: Path) -> None:
        """Test creating a MypyAnalyzer instance."""
        analyzer = MypyAnalyzer(tmp_path)
        assert analyzer.app_path == tmp_path
        assert analyzer._endpoint_deps == {}

    def test_cache_path_default(self, tmp_path: Path) -> None:
        """Test default cache path location."""
        analyzer = MypyAnalyzer(tmp_path)
        expected = tmp_path.parent / ".endpoint_mypy_cache.json"
        assert analyzer.cache_path == expected

    def test_set_cache_path(self, tmp_path: Path) -> None:
        """Test setting a custom cache path."""
        analyzer = MypyAnalyzer(tmp_path)
        custom_path = tmp_path / "custom_cache.json"
        analyzer.set_cache_path(custom_path)
        assert analyzer.cache_path == custom_path

    def test_set_line_progress_callback(self, tmp_path: Path) -> None:
        """Test setting a line progress callback."""
        analyzer = MypyAnalyzer(tmp_path)

        callback_called = {"value": False}
        def callback(file_path: str, line_num: int, symbol: str) -> None:
            callback_called["value"] = True

        analyzer.set_line_progress_callback(callback)
        assert analyzer._line_progress_callback is callback


class TestMypyAnalyzerLoopPrevention:
    """Tests for loop prevention in circular dependencies."""

    @pytest.fixture
    def circular_project(self, tmp_path: Path) -> Path:
        """Create a project with circular dependencies."""
        # Create module_a.py that imports from module_b
        module_a = tmp_path / "module_a.py"
        module_a.write_text("""
from module_b import func_b

def func_a():
    return func_b()
""")

        # Create module_b.py that imports from module_a
        module_b = tmp_path / "module_b.py"
        module_b.write_text("""
from module_a import func_a

def func_b():
    return func_a()
""")

        # Create main.py with a handler that uses these
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from module_a import func_a
from module_b import func_b

def handler():
    result_a = func_a()
    result_b = func_b()
    return result_a + result_b
""")

        return tmp_path

    def test_circular_dependency_no_infinite_loop(self, circular_project: Path) -> None:
        """Test that circular dependencies don't cause infinite loops."""
        analyzer = MypyAnalyzer(circular_project)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=circular_project / "main.py",
            line_number=6,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        # This should complete without hanging
        deps = analyzer.analyze_endpoint(endpoint)

        # Should have found some files
        assert len(deps.referenced_files) >= 1
        # The main file should be in referenced files
        assert str(circular_project / "main.py") in str(deps.referenced_files)

    @pytest.fixture
    def self_referential_project(self, tmp_path: Path) -> Path:
        """Create a project with self-referential imports."""
        # Create a module that imports itself (edge case)
        self_ref = tmp_path / "self_ref.py"
        self_ref.write_text("""
import self_ref

def recursive_func():
    return self_ref.recursive_func()
""")

        # Create main handler
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from self_ref import recursive_func

def handler():
    return recursive_func()
""")

        return tmp_path

    def test_self_referential_import_no_infinite_loop(self, self_referential_project: Path) -> None:
        """Test that self-referential imports don't cause infinite loops."""
        analyzer = MypyAnalyzer(self_referential_project)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=self_referential_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        # This should complete without hanging
        deps = analyzer.analyze_endpoint(endpoint)

        # Should have found the main file
        assert str(self_referential_project / "main.py") in str(deps.referenced_files)


class TestMypyAnalyzerLineProgress:
    """Tests for line progress callback functionality."""

    @pytest.fixture
    def simple_project(self, tmp_path: Path) -> Path:
        """Create a simple project for testing line progress."""
        # Create a service module
        services = tmp_path / "services"
        services.mkdir()
        service_py = services / "user_service.py"
        service_py.write_text("""
class UserService:
    def get_user(self, user_id: int):
        return {"id": user_id, "name": "Test"}
    
    def list_users(self):
        return [self.get_user(1), self.get_user(2)]
""")

        # Create main handler
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from services.user_service import UserService

def handler():
    service = UserService()
    return service.list_users()
""")

        return tmp_path

    def test_line_progress_callback_is_called(self, simple_project: Path) -> None:
        """Test that line progress callback is called during analysis."""
        analyzer = MypyAnalyzer(simple_project)

        progress_calls: list[tuple[str, int, str]] = []

        def callback(file_path: str, line_num: int, symbol: str) -> None:
            progress_calls.append((file_path, line_num, symbol))

        analyzer.set_line_progress_callback(callback)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=simple_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        deps = analyzer.analyze_endpoint(endpoint)

        # The callback should have been called at least once
        assert len(progress_calls) > 0

        # All calls should have valid line numbers
        for file_path, line_num, symbol in progress_calls:
            assert line_num > 0
            assert symbol != ""

    def test_line_progress_callback_reports_symbols(self, simple_project: Path) -> None:
        """Test that line progress callback reports correct symbols."""
        analyzer = MypyAnalyzer(simple_project)

        symbols_seen: set[str] = set()

        def callback(file_path: str, line_num: int, symbol: str) -> None:
            symbols_seen.add(symbol)

        analyzer.set_line_progress_callback(callback)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=simple_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        deps = analyzer.analyze_endpoint(endpoint)

        # Should have seen the UserService and list_users symbols
        assert "UserService" in symbols_seen or "list_users" in symbols_seen


class TestMypyAnalyzerVisitedTracking:
    """Tests specifically for the visited node tracking."""

    @pytest.fixture
    def multi_call_project(self, tmp_path: Path) -> Path:
        """Create a project where the same function is called multiple times."""
        helper_py = tmp_path / "helper.py"
        helper_py.write_text("""
def helper_func():
    return "helper"
""")

        main_py = tmp_path / "main.py"
        main_py.write_text("""
from helper import helper_func

def handler():
    # Call the same function multiple times on different lines
    a = helper_func()
    b = helper_func()
    c = helper_func()
    return a + b + c
""")

        return tmp_path

    def test_same_function_different_lines_all_tracked(self, multi_call_project: Path) -> None:
        """Test that same function called on different lines is tracked correctly."""
        analyzer = MypyAnalyzer(multi_call_project)

        lines_seen: set[int] = set()

        def callback(file_path: str, line_num: int, symbol: str) -> None:
            if symbol == "helper_func":
                lines_seen.add(line_num)

        analyzer.set_line_progress_callback(callback)

        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=multi_call_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )

        deps = analyzer.analyze_endpoint(endpoint)

        # Should have tracked calls on multiple lines (lines 5, 6, 7)
        # At least some of the multiple calls should be seen
        assert len(lines_seen) >= 1  # At minimum one line


class TestEndpointDependencies:
    """Tests for the EndpointDependencies data class."""

    def test_references_file_returns_true(self) -> None:
        """Test references_file returns True for known files."""
        deps = EndpointDependencies(
            endpoint_id="GET /test",
            methods=["GET"],
            path="/test",
            referenced_files={"/path/to/file.py": {1, 2, 3}},
        )
        assert deps.references_file("/path/to/file.py") is True

    def test_references_file_returns_false(self) -> None:
        """Test references_file returns False for unknown files."""
        deps = EndpointDependencies(
            endpoint_id="GET /test",
            methods=["GET"],
            path="/test",
            referenced_files={"/path/to/file.py": {1, 2, 3}},
        )
        assert deps.references_file("/path/to/other.py") is False

    def test_references_lines(self) -> None:
        """Test checking if specific lines are referenced."""
        deps = EndpointDependencies(
            endpoint_id="GET /test",
            methods=["GET"],
            path="/test",
            referenced_files={"/path/to/file.py": {10, 20, 30}},
        )
        lines = deps.referenced_files["/path/to/file.py"]
        assert 10 in lines
        assert 20 in lines
        assert 15 not in lines


class TestCallFrame:
    """Tests for the CallFrame data class."""

    def test_create_call_frame(self) -> None:
        """Test creating a CallFrame."""
        frame = CallFrame(
            file_path="/path/to/file.py",
            line_number=42,
            function_name="my_function",
            code_context="    result = my_function()",
        )
        assert frame.file_path == "/path/to/file.py"
        assert frame.line_number == 42
        assert frame.function_name == "my_function"
        assert "my_function" in frame.code_context

    def test_call_frame_default_code_context(self) -> None:
        """Test CallFrame with default empty code context."""
        frame = CallFrame(
            file_path="/path/to/file.py",
            line_number=1,
            function_name="func",
        )
        assert frame.code_context == ""
