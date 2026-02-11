"""
FastAPI endpoint extractor using runtime introspection.

This module dynamically imports a FastAPI application and extracts
endpoint information using app.routes, which is more reliable than
AST parsing as it handles all FastAPI patterns automatically.
"""

import importlib.util
import inspect
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointMethod,
    HandlerInfo,
)


class FastAPIExtractorError(Exception):
    """Error during FastAPI endpoint extraction."""
    pass


class FastAPIExtractor:
    """
    Extract endpoints from a FastAPI application using runtime introspection.
    
    This approach uses FastAPI's app.routes to get all registered endpoints,
    then uses Python's inspect module to determine handler file locations.
    """

    def __init__(
        self,
        app_path: Path,
        app_variable: str = "app",
        module_name: str | None = None,
    ) -> None:
        """
        Initialize the extractor.
        
        Args:
            app_path: Path to the FastAPI application file or directory.
            app_variable: Name of the FastAPI app variable (default: "app").
            module_name: Optional module name to import. If not provided,
                        will be derived from app_path.
        """
        self.app_path = app_path.resolve()
        self.app_variable = app_variable
        self.module_name = module_name
        self._app: Any = None
        self._original_sys_path: list[str] = []

    def _setup_import_path(self) -> None:
        """Add the app directory to sys.path for importing."""
        self._original_sys_path = sys.path.copy()

        if self.app_path.is_file():
            # Add parent directory to path
            parent_dir = str(self.app_path.parent)
            if parent_dir not in sys.path:
                sys.path.insert(0, parent_dir)
        else:
            # Add the directory itself to path
            dir_path = str(self.app_path)
            if dir_path not in sys.path:
                sys.path.insert(0, dir_path)

    def _restore_import_path(self) -> None:
        """Restore original sys.path."""
        sys.path = self._original_sys_path

    def _load_app(self) -> Any:
        """
        Dynamically load the FastAPI application.
        
        Returns:
            The FastAPI application instance.
            
        Raises:
            FastAPIExtractorError: If the app cannot be loaded.
        """
        if self._app is not None:
            return self._app

        self._setup_import_path()

        try:
            if self.app_path.is_file():
                # Load from a specific file
                module_name = self.module_name or self.app_path.stem
                spec = importlib.util.spec_from_file_location(
                    module_name,
                    self.app_path,
                )
                if spec is None or spec.loader is None:
                    raise FastAPIExtractorError(
                        f"Could not create module spec for {self.app_path}"
                    )

                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
            else:
                # Load from a package/directory
                module_name = self.module_name or self.app_path.name
                module = importlib.import_module(module_name)

            # Get the app variable
            if not hasattr(module, self.app_variable):
                raise FastAPIExtractorError(
                    f"Module does not have '{self.app_variable}' attribute. "
                    f"Available attributes: {dir(module)}"
                )

            self._app = getattr(module, self.app_variable)
            return self._app

        except Exception as e:
            raise FastAPIExtractorError(f"Failed to load FastAPI app: {e}") from e
        finally:
            self._restore_import_path()

    def _get_handler_info(self, handler: Callable[..., Any]) -> HandlerInfo:
        """
        Extract information about a route handler function.
        
        Args:
            handler: The route handler function.
            
        Returns:
            HandlerInfo with file path and line numbers.
        """
        # Unwrap any decorators to get the original function
        original = inspect.unwrap(handler)

        try:
            file_path = Path(inspect.getfile(original))
        except (TypeError, OSError):
            # Built-in or C extension
            file_path = Path("<unknown>")

        try:
            source_lines, start_line = inspect.getsourcelines(original)
            end_line = start_line + len(source_lines) - 1
        except (TypeError, OSError):
            start_line = 0
            end_line = None

        # Get the module name
        module_name = getattr(original, "__module__", "<unknown>")

        # Get the function name, handling callable classes
        func_name = getattr(original, "__name__", None)
        if func_name is None:
            # Might be a callable class instance
            func_name = type(original).__name__

        return HandlerInfo(
            name=func_name,
            module=module_name,
            file_path=file_path,
            line_number=start_line,
            end_line_number=end_line,
        )

    def _extract_dependencies(self, route: Any) -> list[str]:
        """
        Extract FastAPI Depends() dependencies from a route.
        
        Args:
            route: A FastAPI route object.
            
        Returns:
            List of dependency function names.
        """
        dependencies: list[str] = []

        # Check route-level dependencies
        if hasattr(route, "dependencies"):
            for dep in route.dependencies or []:
                if hasattr(dep, "dependency"):
                    dep_func = dep.dependency
                    if callable(dep_func):
                        dep_name = getattr(dep_func, "__name__", None) or type(dep_func).__name__
                        dependencies.append(dep_name)

        # Check endpoint signature for Depends parameters
        if hasattr(route, "endpoint") and callable(route.endpoint):
            try:
                sig = inspect.signature(route.endpoint)
                for param in sig.parameters.values():
                    if param.default is not inspect.Parameter.empty:
                        default = param.default
                        # Check if it's a Depends instance
                        if type(default).__name__ == "Depends":
                            if hasattr(default, "dependency") and default.dependency:
                                dep = default.dependency
                                dep_name = getattr(dep, "__name__", None) or type(dep).__name__
                                dependencies.append(dep_name)
            except (ValueError, TypeError):
                pass

        return dependencies

    def extract_endpoints(self) -> list[Endpoint]:
        """
        Extract all endpoints from the FastAPI application.
        
        Returns:
            List of Endpoint objects representing all routes.
            
        Raises:
            FastAPIExtractorError: If extraction fails.
        """
        app = self._load_app()
        endpoints: list[Endpoint] = []

        # Check if app has routes attribute
        if not hasattr(app, "routes"):
            raise FastAPIExtractorError(
                f"Object '{self.app_variable}' does not have 'routes' attribute. "
                "Is it a FastAPI application?"
            )

        for route in app.routes:
            # Skip non-API routes (like docs, openapi, etc.)
            route_class_name = type(route).__name__

            if route_class_name == "APIRoute":
                # Standard API route
                handler = route.endpoint
                handler_info = self._get_handler_info(handler)

                # Get HTTP methods
                methods = [
                    EndpointMethod(m.upper())
                    for m in route.methods
                    if m.upper() in EndpointMethod.__members__
                ]

                # Get tags
                tags = list(route.tags) if route.tags else []

                # Get dependencies
                dependencies = self._extract_dependencies(route)

                endpoint = Endpoint(
                    path=route.path,
                    methods=methods,
                    handler=handler_info,
                    name=route.name,
                    tags=tags,
                    dependencies=dependencies,
                )
                endpoints.append(endpoint)

            elif route_class_name == "Mount":
                # Mounted sub-application - could be another FastAPI app
                # or static files. Skip for now but log.
                pass

        return endpoints

    def get_endpoint_handler_files(self) -> dict[Path, list[Endpoint]]:
        """
        Group endpoints by their handler file.
        
        Returns:
            Dictionary mapping file paths to endpoints defined in that file.
        """
        endpoints = self.extract_endpoints()
        by_file: dict[Path, list[Endpoint]] = {}

        for endpoint in endpoints:
            file_path = endpoint.handler.file_path
            if file_path not in by_file:
                by_file[file_path] = []
            by_file[file_path].append(endpoint)

        return by_file
