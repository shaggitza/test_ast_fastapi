"""
Secure FastAPI endpoint extractor using pure AST analysis.

This module extracts FastAPI endpoints using only AST parsing without
executing or importing any code. This is safe for analyzing untrusted code.
"""

import ast
from pathlib import Path
from typing import List, Optional, Set

from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointMethod,
    HandlerInfo,
)


class SecureASTExtractorError(Exception):
    """Error during secure AST extraction."""
    pass


class SecureASTExtractor:
    """
    Extract endpoints from FastAPI application using pure AST analysis.
    
    This approach is completely safe as it never imports or executes code.
    It analyzes the AST to find route decorators and endpoint definitions.
    """
    
    # HTTP method names that FastAPI supports
    HTTP_METHODS = {
        'get', 'post', 'put', 'patch', 'delete',
        'options', 'head', 'trace', 'websocket'
    }
    
    def __init__(
        self,
        app_path: Path,
        app_variable: str = "app",
    ) -> None:
        """
        Initialize the secure AST extractor.
        
        Args:
            app_path: Path to the FastAPI application file or directory.
            app_variable: Name of the FastAPI app variable (default: "app").
        """
        self.app_path = app_path.resolve()
        self.app_variable = app_variable
        self._endpoints: List[Endpoint] = []
    
    def extract_endpoints(self) -> List[Endpoint]:
        """
        Extract all endpoints using AST analysis only.
        
        Returns:
            List of discovered endpoints.
        """
        self._endpoints = []
        
        # Find all Python files to analyze
        python_files = self._find_python_files()
        
        # Analyze each file for endpoints
        for file_path in python_files:
            try:
                self._analyze_file(file_path)
            except Exception as e:
                # Continue analyzing other files even if one fails
                pass
        
        return self._endpoints
    
    def _find_python_files(self) -> List[Path]:
        """Find all Python files to analyze."""
        if self.app_path.is_file():
            return [self.app_path]
        else:
            # Recursively find all .py files
            return list(self.app_path.rglob("*.py"))
    
    def _analyze_file(self, file_path: Path) -> None:
        """
        Analyze a single Python file for FastAPI endpoints.
        
        Args:
            file_path: Path to the Python file.
        """
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError:
            # Skip files with syntax errors
            return
        
        # Find route decorators
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                try:
                    endpoints = self._extract_endpoints_from_function(node, file_path)
                    self._endpoints.extend(endpoints)
                except Exception:
                    # Continue analyzing other functions even if one fails
                    pass
    
    def _extract_endpoints_from_function(
        self, 
        func_node: ast.FunctionDef, 
        file_path: Path
    ) -> List[Endpoint]:
        """
        Extract endpoints from a function's decorators.
        
        Args:
            func_node: The function definition AST node.
            file_path: Path to the file containing the function.
            
        Returns:
            List of endpoints found for this function.
        """
        endpoints = []
        
        for decorator in func_node.decorator_list:
            route_info = self._parse_route_decorator(decorator)
            if route_info:
                method, path = route_info
                
                # Get module name from file path
                # Simple approach: use the file stem as module name
                module_name = file_path.stem
                
                # Get handler information
                handler_info = HandlerInfo(
                    name=func_node.name,
                    module=module_name,
                    file_path=file_path,
                    line_number=func_node.lineno,
                    end_line_number=func_node.end_lineno or func_node.lineno,
                )
                
                # Create endpoint
                endpoint = Endpoint(
                    path=path,
                    methods=[EndpointMethod(method.upper())],
                    handler=handler_info,
                )
                
                endpoints.append(endpoint)
        
        return endpoints
    
    def _parse_route_decorator(self, decorator: ast.expr) -> Optional[tuple[str, str]]:
        """
        Parse a route decorator to extract HTTP method and path.
        
        Args:
            decorator: The decorator AST node.
            
        Returns:
            Tuple of (method, path) if this is a route decorator, None otherwise.
        """
        # Handle decorator calls like @app.get("/path")
        if isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Attribute):
                method_name = decorator.func.attr
                
                # Check if this is a FastAPI route decorator
                if method_name in self.HTTP_METHODS:
                    # Check if it's called on an app or router object
                    if isinstance(decorator.func.value, ast.Name):
                        obj_name = decorator.func.value.id
                        
                        # Look for path in the first argument
                        if decorator.args and isinstance(decorator.args[0], ast.Constant):
                            path = decorator.args[0].value
                            if isinstance(path, str):
                                return (method_name, path)
        
        return None
    
    def _is_fastapi_app_creation(self, node: ast.AST) -> bool:
        """
        Check if an AST node creates a FastAPI app.
        
        Args:
            node: The AST node to check.
            
        Returns:
            True if this creates a FastAPI app, False otherwise.
        """
        # Look for patterns like: app = FastAPI()
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id in (self.app_variable, "router", "api", "application"):
                        # Check if the value is a call to FastAPI or APIRouter
                        if isinstance(node.value, ast.Call):
                            if isinstance(node.value.func, ast.Name):
                                if node.value.func.id in ("FastAPI", "APIRouter"):
                                    return True
        
        return False
    
    def _find_router_includes(self, tree: ast.Module) -> List[tuple[str, str]]:
        """
        Find router include statements in the AST.
        
        Args:
            tree: The module AST.
            
        Returns:
            List of (router_var, prefix) tuples.
        """
        includes = []
        
        for node in ast.walk(tree):
            # Look for app.include_router(router, prefix="/api")
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "include_router":
                        # Extract router variable and prefix
                        router_var = None
                        prefix = ""
                        
                        if node.args and isinstance(node.args[0], ast.Name):
                            router_var = node.args[0].id
                        
                        # Look for prefix in kwargs
                        for keyword in node.keywords:
                            if keyword.arg == "prefix":
                                if isinstance(keyword.value, ast.Constant):
                                    prefix = keyword.value.value
                        
                        if router_var:
                            includes.append((router_var, prefix))
        
        return includes
