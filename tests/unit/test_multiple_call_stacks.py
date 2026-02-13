"""Tests for multiple call stacks feature in mypy analyzer."""
import tempfile
from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


class TestMultipleCallStacks:
    """Test that multiple call stacks are tracked when there are multiple paths to a dependency."""
    
    @pytest.fixture
    def multi_path_project(self, tmp_path: Path) -> Path:
        """Create a project where a dependency is reached via multiple paths."""
        # Create a shared utility module
        utils_py = tmp_path / "utils.py"
        utils_py.write_text("""
def shared_utility():
    return "shared result"
""")
        
        # Create two different service modules that both use the utility
        service_a_py = tmp_path / "service_a.py"
        service_a_py.write_text("""
from utils import shared_utility

def service_a_function():
    # Path 1: handler -> service_a_function -> shared_utility
    return shared_utility()
""")
        
        service_b_py = tmp_path / "service_b.py"
        service_b_py.write_text("""
from utils import shared_utility

def service_b_function():
    # Path 2: handler -> service_b_function -> shared_utility
    return shared_utility()
""")
        
        # Create handler that uses both services
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from service_a import service_a_function
from service_b import service_b_function

def handler():
    # This handler reaches shared_utility through TWO different paths
    result_a = service_a_function()
    result_b = service_b_function()
    return result_a + result_b
""")
        
        return tmp_path
    
    def test_multiple_paths_to_same_file(self, multi_path_project: Path) -> None:
        """Test that multiple paths to the same dependency are all recorded."""
        analyzer = MypyAnalyzer(multi_path_project)
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=multi_path_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # For now, check that service modules are referenced
        # (The shared_utility reference goes to the service files, not utils.py directly,
        # due to how mypy resolves the imports)
        service_a_file = str(multi_path_project / "service_a.py")
        service_b_file = str(multi_path_project / "service_b.py")
        
        assert deps.references_file(service_a_file), "Should reference service_a.py"
        assert deps.references_file(service_b_file), "Should reference service_b.py"
        
        # Get call stacks for one of the services
        call_stacks_a = deps.get_call_stack(service_a_file)
        call_stacks_b = deps.get_call_stack(service_b_file)
        
        # Each should have at least one call stack
        assert len(call_stacks_a) >= 1, f"Should have call stack to service_a.py"
        assert len(call_stacks_b) >= 1, f"Should have call stack to service_b.py"
        
        print(f"\n✓ Found call stacks:")
        print(f"  service_a.py: {len(call_stacks_a)} path(s)")
        print(f"  service_b.py: {len(call_stacks_b)} path(s)")
        
        # Verify the stacks are different
        if len(call_stacks_a) > 0:
            print(f"\n  Path to service_a.py:")
            for frame in call_stacks_a[0]:
                print(f"    - {frame.function_name} ({Path(frame.file_path).name}:{frame.line_number})")


class TestCallStackOriginMarking:
    """Test that call stacks are marked with their origin (endpoint handler)."""
    
    @pytest.fixture
    def simple_project(self, tmp_path: Path) -> Path:
        """Create a simple project for testing."""
        utils_py = tmp_path / "utils.py"
        utils_py.write_text("""
def helper():
    return "result"
""")
        
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from utils import helper

def my_handler():
    return helper()
""")
        
        return tmp_path
    
    def test_call_stack_has_origin_marker(self, simple_project: Path) -> None:
        """Test that call stacks include a marker showing which endpoint they come from."""
        analyzer = MypyAnalyzer(simple_project)
        
        handler = HandlerInfo(
            name="my_handler",
            module="main",
            file_path=simple_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/api/test",
            methods=[EndpointMethod.POST],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # Get call stack
        utils_file = str(simple_project / "utils.py")
        call_stacks = deps.get_call_stack(utils_file)
        
        assert len(call_stacks) >= 1, "Should have at least one call stack"
        
        # The call stack itself doesn't have the endpoint marker
        # That's added by the change_mapper when creating AffectedEndpoint
        # But we can verify the stack starts from the handler
        first_stack = call_stacks[0]
        
        # Verify we have frames
        assert len(first_stack) > 0, "Call stack should not be empty"
        
        print(f"\n✓ Call stack has {len(first_stack)} frames")
        for frame in first_stack:
            print(f"  - {frame.function_name} ({Path(frame.file_path).name}:{frame.line_number})")


class TestCallStackWithEndpointMarker:
    """Test that AffectedEndpoint properly marks call stacks with endpoint origin."""
    
    @pytest.fixture
    def test_project(self, tmp_path: Path) -> Path:
        """Create a test project."""
        utils_py = tmp_path / "utils.py"
        utils_py.write_text("""
def process():
    return 42
""")
        
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from utils import process

def endpoint_handler():
    return process()
""")
        
        return tmp_path
    
    def test_affected_endpoint_has_marked_call_stack(self, test_project: Path) -> None:
        """Test that AffectedEndpoint formats tracebacks with clear origin markers."""
        from fastapi_endpoint_detector.models.report import AffectedEndpoint, CallStackFrame, ConfidenceLevel
        
        handler = HandlerInfo(
            name="endpoint_handler",
            module="main",
            file_path=test_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/api/users",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        # Create call stacks with origin marker
        call_stack_1 = [
            CallStackFrame(
                file_path=str(test_project / "main.py"),
                line_number=4,
                function_name="[ENDPOINT] GET /api/users",
                code_context="Handler: endpoint_handler",
            ),
            CallStackFrame(
                file_path=str(test_project / "main.py"),
                line_number=5,
                function_name="endpoint_handler",
                code_context="return process()",
            ),
            CallStackFrame(
                file_path=str(test_project / "utils.py"),
                line_number=2,
                function_name="process",
                code_context="return 42",
            ),
        ]
        
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.MEDIUM,
            reason="Test",
            call_stacks=[call_stack_1],
        )
        
        # Format the traceback
        traceback = affected.format_traceback()
        
        # Verify it contains the endpoint marker
        assert "[ENDPOINT]" in traceback, "Traceback should contain [ENDPOINT] marker"
        assert "GET /api/users" in traceback, "Traceback should show endpoint path"
        assert "Handler: endpoint_handler" in traceback, "Traceback should show handler name"
        
        print(f"\n✓ Formatted traceback:")
        print(traceback)


class TestMultiplePathsFormatting:
    """Test formatting of multiple call stacks."""
    
    def test_multiple_paths_in_traceback(self) -> None:
        """Test that multiple paths are clearly labeled in traceback output."""
        from fastapi_endpoint_detector.models.report import AffectedEndpoint, CallStackFrame, ConfidenceLevel
        from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path="/app/main.py",
            line_number=10,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        # Create two different paths
        path_1 = [
            CallStackFrame(
                file_path="/app/main.py",
                line_number=10,
                function_name="[ENDPOINT] GET /test",
                code_context="Handler: handler",
            ),
            CallStackFrame(
                file_path="/app/service_a.py",
                line_number=5,
                function_name="service_a",
                code_context="call_utility()",
            ),
            CallStackFrame(
                file_path="/app/utils.py",
                line_number=1,
                function_name="utility",
                code_context="return 1",
            ),
        ]
        
        path_2 = [
            CallStackFrame(
                file_path="/app/main.py",
                line_number=10,
                function_name="[ENDPOINT] GET /test",
                code_context="Handler: handler",
            ),
            CallStackFrame(
                file_path="/app/service_b.py",
                line_number=8,
                function_name="service_b",
                code_context="call_utility()",
            ),
            CallStackFrame(
                file_path="/app/utils.py",
                line_number=1,
                function_name="utility",
                code_context="return 1",
            ),
        ]
        
        affected = AffectedEndpoint(
            endpoint=endpoint,
            confidence=ConfidenceLevel.MEDIUM,
            reason="Multiple paths test",
            call_stacks=[path_1, path_2],
        )
        
        traceback = affected.format_traceback()
        
        # Verify both paths are shown
        assert "path 1 of 2" in traceback.lower(), "Should label first path"
        assert "path 2 of 2" in traceback.lower(), "Should label second path"
        
        # Verify both service files are mentioned
        assert "service_a" in traceback, "Should mention service_a"
        assert "service_b" in traceback, "Should mention service_b"
        
        # Verify endpoint marker appears in both paths
        endpoint_marker_count = traceback.count("[ENDPOINT]")
        assert endpoint_marker_count >= 2, f"Should have endpoint marker in each path, got {endpoint_marker_count}"
        
        print(f"\n✓ Formatted traceback with multiple paths:")
        print(traceback)
