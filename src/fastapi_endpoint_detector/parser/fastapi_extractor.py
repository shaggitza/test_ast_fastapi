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
from typing import Any, cast

import fastapi.routing as fastapi_routing
from fastapi.routing import APIRoute, APIWebSocketRoute
from starlette.routing import Mount

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
                    raise FastAPIExtractorError(f"Could not create module spec for {self.app_path}")

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
                        if (
                            type(default).__name__ == "Depends"
                            and hasattr(default, "dependency")
                            and default.dependency
                        ):
                            dep = default.dependency
                            dep_name = getattr(dep, "__name__", None) or type(dep).__name__
                            dependencies.append(dep_name)
            except (ValueError, TypeError):
                pass

        return dependencies

    @staticmethod
    def _join_paths(prefix: str, path: str) -> str:
        """Join effective include and mount paths without losing root slashes."""
        if not prefix:
            return path if path.startswith("/") else f"/{path}" if path else "/"
        normalized_prefix = prefix if prefix.startswith("/") else f"/{prefix}"
        normalized_prefix = normalized_prefix.rstrip("/")
        if path == "/":
            return f"{normalized_prefix}/" if normalized_prefix else "/"
        return f"{normalized_prefix}/{path.lstrip('/')}" if path else normalized_prefix

    @staticmethod
    def _require_route_path(
        route: Any,
        original_route: Any,
        *,
        allow_empty: bool = False,
    ) -> str:
        path = getattr(route, "path", None)
        if isinstance(path, str) and (path or allow_empty):
            return path
        effective_route = getattr(route, "starlette_route", None)
        effective_path = getattr(effective_route, "path", None)
        if isinstance(effective_path, str) and (effective_path or allow_empty):
            return effective_path
        raise FastAPIExtractorError(
            f"FastAPI route '{type(original_route).__name__}' has no effective path"
        )

    @staticmethod
    def _require_route_endpoint(route: Any, original_route: Any) -> Callable[..., Any]:
        endpoint = getattr(route, "endpoint", None)
        if callable(endpoint):
            return cast("Callable[..., Any]", endpoint)
        effective_route = getattr(route, "starlette_route", None)
        effective_endpoint = getattr(effective_route, "endpoint", None)
        if callable(effective_endpoint):
            return cast("Callable[..., Any]", effective_endpoint)
        raise FastAPIExtractorError(
            f"FastAPI route '{type(original_route).__name__}' has no callable endpoint"
        )

    @staticmethod
    def _effective_route_metadata(route: Any) -> Any:
        path = getattr(route, "path", None)
        endpoint = getattr(route, "endpoint", None)
        if isinstance(path, str) and path and callable(endpoint):
            return route
        return getattr(route, "starlette_route", None) or route

    @staticmethod
    def _http_methods(route: Any, original_route: Any) -> list[EndpointMethod]:
        raw_methods = getattr(route, "methods", None)
        if not raw_methods:
            raise FastAPIExtractorError(
                f"FastAPI route '{type(original_route).__name__}' has no HTTP methods"
            )
        if any(not isinstance(method, str) for method in raw_methods):
            raise FastAPIExtractorError(
                f"FastAPI route '{type(original_route).__name__}' has invalid HTTP methods"
            )
        normalized_methods = {method.upper() for method in raw_methods}
        supported_methods = {
            method.value
            for method in EndpointMethod
            if method not in {EndpointMethod.WEBSOCKET, EndpointMethod.CUSTOM}
        }
        unsupported_methods = normalized_methods - supported_methods
        if unsupported_methods:
            unsupported = ", ".join(sorted(unsupported_methods))
            raise FastAPIExtractorError(f"Unsupported FastAPI HTTP methods: {unsupported}")
        return [EndpointMethod(method) for method in sorted(normalized_methods)]

    def _http_endpoint(self, route: Any, original_route: Any, prefix: str) -> Endpoint:
        path = self._require_route_path(route, original_route)
        endpoint = self._require_route_endpoint(route, original_route)
        return Endpoint(
            path=self._join_paths(prefix, path),
            methods=self._http_methods(route, original_route),
            handler=self._get_handler_info(endpoint),
            name=getattr(route, "name", None),
            tags=list(getattr(route, "tags", None) or []),
            dependencies=self._extract_dependencies(route),
        )

    def _websocket_endpoint(self, route: Any, original_route: Any, prefix: str) -> Endpoint:
        metadata = self._effective_route_metadata(route)
        return Endpoint(
            path=self._join_paths(prefix, self._require_route_path(metadata, original_route)),
            methods=[EndpointMethod.WEBSOCKET],
            handler=self._get_handler_info(self._require_route_endpoint(metadata, original_route)),
            name=getattr(metadata, "name", None),
            dependencies=self._extract_dependencies(metadata),
        )

    def _endpoints_from_route(
        self,
        route: Any,
        prefix: str,
        stack: frozenset[int],
    ) -> list[Endpoint]:
        original_route = getattr(route, "original_route", route)
        if isinstance(original_route, APIRoute):
            return [self._http_endpoint(route, original_route, prefix)]
        if isinstance(original_route, APIWebSocketRoute):
            return [self._websocket_endpoint(route, original_route, prefix)]
        if isinstance(original_route, Mount):
            child_routes = getattr(original_route, "routes", None)
            if child_routes is None:
                return []
            effective_mount = self._effective_route_metadata(route)
            mount_path = self._require_route_path(
                effective_mount,
                original_route,
                allow_empty=True,
            )
            return self._walk_routes(
                child_routes,
                prefix=self._join_paths(prefix, mount_path),
                stack=stack,
            )
        if (
            getattr(original_route, "original_router", None) is not None
            or getattr(original_route, "include_context", None) is not None
        ):
            raise FastAPIExtractorError(
                "Unsupported included FastAPI router representation "
                f"'{type(original_route).__name__}'"
            )
        return []

    def _walk_routes(
        self,
        routes: Any,
        prefix: str = "",
        stack: frozenset[int] = frozenset(),
    ) -> list[Endpoint]:
        route_collection_id = id(routes)
        if route_collection_id in stack:
            return []
        next_stack = stack | {route_collection_id}
        normalize = getattr(fastapi_routing, "iter_route_contexts", None)
        normalized_routes = normalize(routes) if callable(normalize) else iter(routes)
        endpoints: list[Endpoint] = []
        try:
            for route in normalized_routes:
                endpoints.extend(self._endpoints_from_route(route, prefix, next_stack))
        except FastAPIExtractorError:
            raise
        except Exception as exc:
            raise FastAPIExtractorError(f"Failed to inspect FastAPI routes: {exc}") from exc
        return endpoints

    def extract_endpoints(self) -> list[Endpoint]:
        """
        Extract all endpoints from the FastAPI application.

        Returns:
            List of Endpoint objects representing all routes.

        Raises:
            FastAPIExtractorError: If extraction fails.
        """
        app = self._load_app()
        if not hasattr(app, "routes"):
            raise FastAPIExtractorError(
                f"Object '{self.app_variable}' does not have 'routes' attribute. "
                "Is it a FastAPI application?"
            )
        endpoints = self._walk_routes(app.routes)
        return sorted(endpoints, key=lambda endpoint: endpoint.identifier)

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
