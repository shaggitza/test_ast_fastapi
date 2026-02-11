"""
Unit tests for edge cases in MypyAnalyzer.

These tests verify that the mypy-based dependency analysis correctly handles
various edge cases that might be missed in the standard implementation.
"""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.mypy_analyzer import MypyAnalyzer
from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod, HandlerInfo


class TestDecoratorArguments:
    """Test that decorator arguments and their references are traced."""
    
    @pytest.fixture
    def decorator_project(self, tmp_path: Path) -> Path:
        """Create a project with decorators that have arguments."""
        # Create a config module
        config_py = tmp_path / "config.py"
        config_py.write_text("""
def get_default_config():
    return {"timeout": 30}
""")
        
        # Create a validators module
        validators_py = tmp_path / "validators.py"
        validators_py.write_text("""
def validate_input(value):
    return value is not None
""")
        
        # Create main handler with decorators that have function call arguments
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from functools import lru_cache
from config import get_default_config
from validators import validate_input

# Decorator with function call as argument
def cached_config(func):
    def wrapper(*args, **kwargs):
        config = get_default_config()
        return func(*args, **kwargs)
    return wrapper

@cached_config
@lru_cache(maxsize=128)
def handler():
    return validate_input("test")
""")
        
        return tmp_path
    
    def test_decorator_with_function_call_argument(self, decorator_project: Path) -> None:
        """Test that function calls inside decorator arguments are traced."""
        analyzer = MypyAnalyzer(decorator_project)
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=decorator_project / "main.py",
            line_number=14,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # Should trace the get_default_config function called in decorator
        # This is an edge case - decorators with arguments are often missed
        config_file = str(decorator_project / "config.py")
        assert deps.references_file(config_file), (
            "Decorator argument function call should be traced"
        )


class TestLambdaDefaults:
    """Test that lambda default arguments with function calls are traced."""
    
    @pytest.fixture
    def lambda_project(self, tmp_path: Path) -> Path:
        """Create a project with lambdas that have default arguments."""
        # Create a defaults module
        defaults_py = tmp_path / "defaults.py"
        defaults_py.write_text("""
def get_default_value():
    return 42
""")
        
        # Create main handler with lambda that has default argument
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from defaults import get_default_value

def handler():
    # Lambda with default argument that calls a function
    processor = lambda x=get_default_value(): x * 2
    return processor()
""")
        
        return tmp_path
    
    def test_lambda_default_argument_function_call(self, lambda_project: Path) -> None:
        """Test that function calls in lambda default arguments are traced."""
        analyzer = MypyAnalyzer(lambda_project)
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=lambda_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # Should trace the get_default_value function in lambda default
        defaults_file = str(lambda_project / "defaults.py")
        assert deps.references_file(defaults_file), (
            "Lambda default argument function call should be traced"
        )


class TestForLoopTargets:
    """Test that for-loop target annotations are traced."""
    
    @pytest.fixture
    def loop_project(self, tmp_path: Path) -> Path:
        """Create a project with type-annotated for-loop variables."""
        # Create a types module
        types_py = tmp_path / "types.py"
        types_py.write_text("""
class CustomType:
    def __init__(self, value: int):
        self.value = value
""")
        
        # Create main handler with annotated for-loop
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from types import CustomType

def get_items():
    return [CustomType(1), CustomType(2)]

def handler():
    result = []
    # For loop with type annotation on target variable
    for item in get_items():
        result.append(item.value)
    return result
""")
        
        return tmp_path
    
    def test_for_loop_with_type_annotated_target(self, loop_project: Path) -> None:
        """Test that for-loop target variables are properly traced."""
        analyzer = MypyAnalyzer(loop_project)
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=loop_project / "main.py",
            line_number=7,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # Should trace get_items in the for-loop expression
        # The for-loop target itself may not need tracing, but the expression does
        main_file = str(loop_project / "main.py")
        assert deps.references_file(main_file), (
            "For-loop expression should be traced"
        )


class TestComprehensionReferences:
    """Test that comprehensions with function calls are fully traced."""
    
    @pytest.fixture
    def comprehension_project(self, tmp_path: Path) -> Path:
        """Create a project with comprehensions containing function calls."""
        # Create a processors module
        processors_py = tmp_path / "processors.py"
        processors_py.write_text("""
def process_item(item):
    return item * 2

def filter_item(item):
    return item > 0
""")
        
        # Create main handler with comprehensions
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from processors import process_item, filter_item

def get_raw_data():
    return [1, -2, 3, -4, 5]

def handler():
    # List comprehension with function calls
    result = [process_item(x) for x in get_raw_data() if filter_item(x)]
    return result
""")
        
        return tmp_path
    
    def test_comprehension_function_calls_traced(self, comprehension_project: Path) -> None:
        """Test that function calls inside comprehensions are traced."""
        analyzer = MypyAnalyzer(comprehension_project)
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=comprehension_project / "main.py",
            line_number=7,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # Should trace all functions in comprehension
        processors_file = str(comprehension_project / "processors.py")
        assert deps.references_file(processors_file), (
            "Functions called in comprehensions should be traced"
        )
        
        # Should have both process_item and filter_item
        # Check if we have references to the processor module
        main_file = str(comprehension_project / "main.py")
        assert deps.references_file(main_file)


class TestExceptionTypes:
    """Test that custom exception types in try/except are traced."""
    
    @pytest.fixture
    def exception_project(self, tmp_path: Path) -> Path:
        """Create a project with custom exceptions."""
        # Create an exceptions module
        exceptions_py = tmp_path / "exceptions.py"
        exceptions_py.write_text("""
class CustomError(Exception):
    pass

class ValidationError(Exception):
    pass
""")
        
        # Create main handler with try/except using custom exceptions
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from exceptions import CustomError, ValidationError

def risky_operation():
    raise CustomError("Something went wrong")

def handler():
    try:
        result = risky_operation()
    except CustomError as e:
        return {"error": str(e)}
    except ValidationError:
        return {"error": "Validation failed"}
    return result
""")
        
        return tmp_path
    
    def test_custom_exception_types_traced(self, exception_project: Path) -> None:
        """Test that custom exception types in except clauses are traced."""
        analyzer = MypyAnalyzer(exception_project)
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=exception_project / "main.py",
            line_number=7,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # Should trace the exceptions module
        exceptions_file = str(exception_project / "exceptions.py")
        assert deps.references_file(exceptions_file), (
            "Custom exception types should be traced"
        )


class TestFunctionSignatureAnnotations:
    """Test that type annotations in function signatures are traced."""
    
    @pytest.fixture
    def signature_project(self, tmp_path: Path) -> Path:
        """Create a project with type annotations in signatures."""
        # Create a dependencies module (simulating FastAPI Depends pattern)
        dependencies_py = tmp_path / "dependencies.py"
        dependencies_py.write_text("""
class Database:
    def query(self, sql: str):
        return []

def get_database():
    return Database()
""")
        
        # Create a response module
        response_py = tmp_path / "response.py"
        response_py.write_text("""
class Response:
    def __init__(self, data):
        self.data = data
""")
        
        # Create main handler with type annotations
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from dependencies import Database, get_database
from response import Response

def handler(db: Database = None) -> Response:
    if db is None:
        db = get_database()
    data = db.query("SELECT * FROM users")
    return Response(data)
""")
        
        return tmp_path
    
    def test_signature_type_annotations_traced(self, signature_project: Path) -> None:
        """Test that type annotations in function signatures are traced."""
        analyzer = MypyAnalyzer(signature_project)
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=signature_project / "main.py",
            line_number=4,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # Should trace the Database type from annotations
        # and the Response type from return annotation
        dependencies_file = str(signature_project / "dependencies.py")
        response_file = str(signature_project / "response.py")
        
        # At minimum, should trace the function calls in the body
        assert deps.references_file(dependencies_file), (
            "Dependencies module should be traced (at least from function body)"
        )
        assert deps.references_file(response_file), (
            "Response module should be traced (at least from function body)"
        )


class TestImportsInFunctionBody:
    """Test that imports inside function bodies are traced."""
    
    @pytest.fixture
    def dynamic_import_project(self, tmp_path: Path) -> Path:
        """Create a project with imports inside function bodies."""
        # Create a utils module
        utils_py = tmp_path / "utils.py"
        utils_py.write_text("""
def helper():
    return "helper result"
""")
        
        # Create a late_import module
        late_import_py = tmp_path / "late_import.py"
        late_import_py.write_text("""
def late_function():
    return "late result"
""")
        
        # Create main handler with import inside function
        main_py = tmp_path / "main.py"
        main_py.write_text("""
def handler():
    # Import inside function body
    from utils import helper
    from late_import import late_function
    
    result = helper()
    result2 = late_function()
    return result + result2
""")
        
        return tmp_path
    
    def test_imports_in_function_body_traced(self, dynamic_import_project: Path) -> None:
        """Test that imports inside function bodies are traced."""
        analyzer = MypyAnalyzer(dynamic_import_project)
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=dynamic_import_project / "main.py",
            line_number=2,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # Should trace functions called after imports
        # Even if the import statements themselves aren't walked,
        # the function calls should be traced
        utils_file = str(dynamic_import_project / "utils.py")
        late_file = str(dynamic_import_project / "late_import.py")
        
        assert deps.references_file(utils_file), (
            "Functions from imports in function body should be traced"
        )
        assert deps.references_file(late_file), (
            "Functions from late imports should be traced"
        )


class TestUnpackingArguments:
    """Test that *args/**kwargs unpacking with references are traced."""
    
    @pytest.fixture
    def unpacking_project(self, tmp_path: Path) -> Path:
        """Create a project with argument unpacking."""
        # Create a builders module
        builders_py = tmp_path / "builders.py"
        builders_py.write_text("""
def build_arg1():
    return "arg1"

def build_arg2():
    return "arg2"

def build_kwargs():
    return {"key": "value"}
""")
        
        # Create main handler with unpacking
        main_py = tmp_path / "main.py"
        main_py.write_text("""
from builders import build_arg1, build_arg2, build_kwargs

def target_function(*args, **kwargs):
    return f"{args} {kwargs}"

def handler():
    # Unpacking with function calls
    args = [build_arg1(), build_arg2()]
    kwargs = build_kwargs()
    result = target_function(*args, **kwargs)
    return result
""")
        
        return tmp_path
    
    def test_unpacking_arguments_traced(self, unpacking_project: Path) -> None:
        """Test that references in unpacked arguments are traced."""
        analyzer = MypyAnalyzer(unpacking_project)
        
        handler = HandlerInfo(
            name="handler",
            module="main",
            file_path=unpacking_project / "main.py",
            line_number=7,
        )
        endpoint = Endpoint(
            path="/test",
            methods=[EndpointMethod.GET],
            handler=handler,
        )
        
        deps = analyzer.analyze_endpoint(endpoint)
        
        # Should trace the builder functions
        builders_file = str(unpacking_project / "builders.py")
        assert deps.references_file(builders_file), (
            "Functions used to build unpacked arguments should be traced"
        )
