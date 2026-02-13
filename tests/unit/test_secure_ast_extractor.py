"""
Unit tests for SecureASTExtractor.
"""

import ast
from pathlib import Path

import pytest

from fastapi_endpoint_detector.parser.secure_ast_extractor import (
    SecureASTExtractor,
    SecureASTExtractorError,
)


class TestSecureASTExtractor:
    """Tests for SecureASTExtractor class."""
    
    def test_init(self, tmp_path: Path) -> None:
        """Test extractor initialization."""
        app_file = tmp_path / "app.py"
        app_file.write_text("# test")
        
        extractor = SecureASTExtractor(app_path=app_file, app_variable="app")
        
        assert extractor.app_path == app_file.resolve()
        assert extractor.app_variable == "app"
    
    def test_extract_simple_get_endpoint(self, tmp_path: Path) -> None:
        """Test extracting a simple GET endpoint."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def list_users():
    return []
""")
        
        extractor = SecureASTExtractor(app_path=app_file)
        endpoints = extractor.extract_endpoints()
        
        assert len(endpoints) >= 1
        # Find the /users endpoint
        users_endpoint = next((e for e in endpoints if e.path == "/users"), None)
        assert users_endpoint is not None
        assert "GET" in [m.value for m in users_endpoint.methods]
    
    @pytest.mark.parametrize("method", ["get", "post", "put", "patch", "delete"])
    def test_extract_different_http_methods(self, tmp_path: Path, method: str) -> None:
        """Test extracting different HTTP methods."""
        app_file = tmp_path / "app.py"
        app_file.write_text(f"""
from fastapi import FastAPI

app = FastAPI()

@app.{method}("/test")
def handler():
    return {{}}
""")
        
        extractor = SecureASTExtractor(app_path=app_file)
        endpoints = extractor.extract_endpoints()
        
        assert len(endpoints) >= 1
        test_endpoint = next((e for e in endpoints if e.path == "/test"), None)
        assert test_endpoint is not None
        assert method.upper() in [m.value for m in test_endpoint.methods]
    
    def test_extract_multiple_endpoints(self, tmp_path: Path) -> None:
        """Test extracting multiple endpoints from one file."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
def list_users():
    return []

@app.post("/users")
def create_user():
    return {}

@app.get("/items/{item_id}")
def get_item(item_id: int):
    return {}
""")
        
        extractor = SecureASTExtractor(app_path=app_file)
        endpoints = extractor.extract_endpoints()
        
        assert len(endpoints) >= 3
        paths = [e.path for e in endpoints]
        assert "/users" in paths
        assert "/items/{item_id}" in paths
    
    def test_extract_from_router(self, tmp_path: Path) -> None:
        """Test extracting endpoints from APIRouter."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import APIRouter

router = APIRouter()

@router.get("/admin")
def admin_page():
    return {}
""")
        
        extractor = SecureASTExtractor(app_path=app_file)
        endpoints = extractor.extract_endpoints()
        
        # Should find the endpoint even on a router
        admin_endpoint = next((e for e in endpoints if e.path == "/admin"), None)
        assert admin_endpoint is not None
    
    def test_no_code_execution(self, tmp_path: Path) -> None:
        """Test that no code is executed during extraction."""
        app_file = tmp_path / "app.py"
        # This code would crash if executed
        app_file.write_text("""
from fastapi import FastAPI

# This would fail if executed
raise RuntimeError("Code was executed!")

app = FastAPI()

@app.get("/test")
def test_handler():
    return {}
""")
        
        extractor = SecureASTExtractor(app_path=app_file)
        
        # Should not raise RuntimeError because code is not executed
        endpoints = extractor.extract_endpoints()
        
        # Should still find the endpoint
        test_endpoint = next((e for e in endpoints if e.path == "/test"), None)
        assert test_endpoint is not None
    
    def test_handles_syntax_errors_gracefully(self, tmp_path: Path) -> None:
        """Test that syntax errors are handled gracefully."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI(

# Syntax error - unclosed parenthesis
""")
        
        extractor = SecureASTExtractor(app_path=app_file)
        
        # Should not crash, just return empty list
        endpoints = extractor.extract_endpoints()
        assert isinstance(endpoints, list)
    
    def test_extract_from_directory(self, tmp_path: Path) -> None:
        """Test extracting endpoints from a directory."""
        # Create multiple files
        (tmp_path / "main.py").write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {}
""")
        
        (tmp_path / "users.py").write_text("""
from fastapi import APIRouter

router = APIRouter()

@router.get("/users")
def list_users():
    return []
""")
        
        extractor = SecureASTExtractor(app_path=tmp_path)
        endpoints = extractor.extract_endpoints()
        
        # Should find endpoints from both files
        assert len(endpoints) >= 2
        paths = [e.path for e in endpoints]
        assert "/" in paths
        assert "/users" in paths
    
    def test_handler_info_includes_file_and_line(self, tmp_path: Path) -> None:
        """Test that handler info includes file path and line numbers."""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from fastapi import FastAPI

app = FastAPI()

@app.get("/test")
def test_handler():
    return {}
""")
        
        extractor = SecureASTExtractor(app_path=app_file)
        endpoints = extractor.extract_endpoints()
        
        test_endpoint = next((e for e in endpoints if e.path == "/test"), None)
        assert test_endpoint is not None
        assert test_endpoint.handler.file_path == app_file
        assert test_endpoint.handler.line_number > 0
        assert test_endpoint.handler.name == "test_handler"
