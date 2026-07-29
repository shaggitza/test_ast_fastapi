"""
FastAPI endpoint extractor using runtime introspection.

This module dynamically imports a FastAPI application and extracts
endpoint information using app.routes, which is more reliable than
AST parsing as it handles all FastAPI patterns automatically.
"""

import functools
import importlib.util
import inspect
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

import fastapi.routing as fastapi_routing
from fastapi.routing import APIRoute, APIWebSocketRoute
from starlette.routing import Mount

from fastapi_endpoint_detector.models.endpoint import (
    DependencyCallableKind,
    DependencyCallableStructure,
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
        *,
        timeout_seconds: float = 60.0,
        output_limit_bytes: int = 4 * 1024 * 1024,
        dependency_max_depth: int = 32,
        dependency_max_nodes: int = 2048,
        dependency_max_work: int = 8192,
    ) -> None:
        """
        Initialize the extractor.

        Args:
            app_path: Path to the FastAPI application file or directory.
            app_variable: Name of the FastAPI app variable (default: "app").
            module_name: Optional module name to import. If not provided,
                        will be derived from app_path.
            timeout_seconds: Maximum time allowed for runtime import and extraction.
            output_limit_bytes: Maximum serialized worker response size.
            dependency_max_depth: Maximum recursive dependency depth retained.
            dependency_max_nodes: Maximum dependency occurrences retained per endpoint.
            dependency_max_work: Maximum dependency traversal work units per endpoint.
        """
        try:
            normalized_timeout = float(timeout_seconds)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("timeout_seconds must be a finite positive number") from exc
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(normalized_timeout)
            or normalized_timeout <= 0
        ):
            raise ValueError("timeout_seconds must be a finite positive number")
        if (
            isinstance(output_limit_bytes, bool)
            or not isinstance(output_limit_bytes, int)
            or output_limit_bytes <= 0
            or output_limit_bytes > 64 * 1024 * 1024
        ):
            raise ValueError("output_limit_bytes must be a positive integer not exceeding 67108864")
        self.app_path = app_path.resolve()
        self.app_variable = app_variable
        self.module_name = module_name
        self.timeout_seconds = normalized_timeout
        for name, value in (
            ("dependency_max_depth", dependency_max_depth),
            ("dependency_max_nodes", dependency_max_nodes),
            ("dependency_max_work", dependency_max_work),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if dependency_max_depth > 64:
            raise ValueError("dependency_max_depth must not exceed 64")
        if dependency_max_nodes > 4096:
            raise ValueError("dependency_max_nodes must not exceed 4096")
        if dependency_max_work > 65536:
            raise ValueError("dependency_max_work must not exceed 65536")
        self.output_limit_bytes = output_limit_bytes
        self.dependency_max_depth = dependency_max_depth
        self.dependency_max_nodes = dependency_max_nodes
        self.dependency_max_work = dependency_max_work
        self._app: Any = None
        self._original_sys_path: list[str] = []

    def _import_context(self) -> tuple[str, Path]:
        """Return the qualified entry module and the import root that contains it."""
        if self.app_path.is_dir():
            module_name = self.module_name or self.app_path.name
            import_root = self.app_path
            for _part in module_name.split("."):
                import_root = import_root.parent
            return module_name, import_root

        if self.module_name is not None:
            module_name = self.module_name
            package_depth = len(module_name.split("."))
            if self.app_path.name != "__init__.py":
                package_depth -= 1
            import_root = self.app_path.parent
            for _index in range(max(package_depth, 0)):
                import_root = import_root.parent
            return module_name, import_root

        package_parts: list[str] = []
        package_dir = self.app_path.parent
        while (package_dir / "__init__.py").is_file():
            package_parts.insert(0, package_dir.name)
            package_dir = package_dir.parent
        if self.app_path.name != "__init__.py":
            package_parts.append(self.app_path.stem)
        module_name = ".".join(package_parts)
        if not module_name:
            raise FastAPIExtractorError(f"Could not derive module name for {self.app_path}")
        import_root = (
            package_dir
            if self.app_path.name == "__init__.py" or len(package_parts) > 1
            else self.app_path.parent
        )
        return module_name, import_root

    def _setup_import_path(self, import_root: Path) -> None:
        """Add the resolved package root to sys.path for importing."""
        self._original_sys_path = sys.path.copy()
        root = str(import_root)
        if root not in sys.path:
            sys.path.insert(0, root)

    def _restore_import_path(self) -> None:
        """Restore original sys.path in place."""
        sys.path[:] = self._original_sys_path

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

        module_name, import_root = self._import_context()
        self._setup_import_path(import_root)

        try:
            if self.app_path.is_file():
                # Load from a specific file with package-qualified context when available.
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
                # Load from a package/directory using its containing import root.
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
    def _physical_callable(value: Any) -> Any:
        """Return the actual function implementing a callable without decorator unwrapping."""
        candidate = value.func if isinstance(value, functools.partial) else value
        if inspect.ismethod(candidate):
            return candidate.__func__
        if inspect.isfunction(candidate):
            return candidate
        if callable(candidate) and not inspect.isclass(candidate):
            return type(candidate).__call__
        return candidate

    @classmethod
    def _dependency_source_span(cls, value: Any) -> DependencySourceSpan | None:
        """Return source coordinates for the physical callable, never ``__wrapped__``."""
        try:
            candidate = cls._physical_callable(value)
            source_lines, start_line = inspect.getsourcelines(candidate)
            file_path = Path(
                inspect.getsourcefile(candidate) or inspect.getfile(candidate)
            ).resolve()
        except Exception:
            return None
        if start_line < 1:
            return None
        return DependencySourceSpan(
            file_path=file_path,
            start_line=start_line,
            end_line=start_line + len(source_lines) - 1,
        )

    @classmethod
    def _callable_identity(cls, value: Any) -> tuple[str | None, str | None]:
        """Derive physical identity from code/globals, not copyable wrapper metadata."""
        try:
            candidate = cls._physical_callable(value)
            if not inspect.isfunction(candidate):
                return None, None
            globals_dict = getattr(candidate, "__globals__", None)
            code = getattr(candidate, "__code__", None)
            module = globals_dict.get("__name__") if isinstance(globals_dict, dict) else None
            qualname = getattr(code, "co_qualname", None)
            if qualname is None:
                # ``code.co_qualname`` was added in Python 3.11. On 3.10,
                # accept ``__qualname__`` only when copied decorator metadata
                # has not changed the physical code object's function name.
                runtime_name = getattr(candidate, "__name__", None)
                code_name = getattr(code, "co_name", None)
                declared_qualname = getattr(candidate, "__qualname__", None)
                if runtime_name == code_name:
                    qualname = declared_qualname
            if not isinstance(module, str) or not module or len(module) > 512:
                return None, None
            if not isinstance(qualname, str) or not qualname or len(qualname) > 1024:
                return None, None
        except Exception:
            return None, None
        return module, qualname

    @staticmethod
    def _callable_kind(value: Any) -> DependencyCallableKind:
        if isinstance(value, functools.partial):
            return DependencyCallableKind.PARTIAL
        if inspect.ismethod(value) and value.__self__ is not None:
            return DependencyCallableKind.BOUND_METHOD
        if inspect.isfunction(value):
            return DependencyCallableKind.FUNCTION
        if callable(value) and not inspect.isclass(value):
            return DependencyCallableKind.CALLABLE_INSTANCE
        return DependencyCallableKind.UNKNOWN

    def _callable_structure(  # noqa: PLR0912, PLR0915
        self, value: Any
    ) -> tuple[tuple[DependencyCallableStructure, ...], tuple[str, ...]]:
        """Describe callable shape without scanning metadata beyond retention bounds."""
        layers: list[DependencyCallableStructure] = []
        limitations: list[str] = []
        current = value

        def note(code: str) -> None:
            if code not in limitations:
                limitations.append(code)

        while len(layers) < 8:
            kind = self._callable_kind(current)
            module, qualname = self._callable_identity(current)
            positional_count = 0
            keyword_names: tuple[str, ...] = ()
            if isinstance(current, functools.partial):
                args_available, raw_args = self._safe_attribute(current, "args")
                if not args_available or type(raw_args) is not tuple:
                    note("callable_arguments_invalid_shape")
                else:
                    positional_count = len(raw_args)
                    if positional_count > 1024:
                        note("callable_positional_count_truncated")

                keywords_available, raw_keywords = self._safe_attribute(current, "keywords")
                if not keywords_available or (
                    raw_keywords is not None and type(raw_keywords) is not dict
                ):
                    note("callable_keywords_invalid_shape")
                elif raw_keywords is not None:
                    keyword_count = len(raw_keywords)
                    if keyword_count > 128:
                        # Count first: over-cap maps retain no key-level evidence and are
                        # never iterated, materialized, or sorted.
                        note("callable_keyword_names_truncated")
                    else:
                        bounded_names: list[str] = []
                        invalid_name = False
                        for name in raw_keywords:
                            if type(name) is not str or not name:
                                invalid_name = True
                            else:
                                bounded_names.append(name)
                        if invalid_name:
                            note("callable_keyword_names_invalid_shape")
                        else:
                            bounded_names.sort()
                            if any(len(name) > 256 for name in bounded_names):
                                note("callable_keyword_name_truncated")
                            keyword_names = tuple(name[:256] for name in bounded_names)

            layers.append(
                DependencyCallableStructure(
                    kind=kind,
                    module=module,
                    qualname=qualname,
                    bound_positional_count=min(positional_count, 1024),
                    bound_keyword_names=keyword_names,
                )
            )
            if not isinstance(current, functools.partial):
                break
            func_available, next_callable = self._safe_attribute(current, "func")
            if not func_available:
                note("callable_structure_invalid_shape")
                break
            current = next_callable
        if len(layers) == 8 and layers[-1].kind == DependencyCallableKind.PARTIAL:
            note("callable_structure_truncated")
        return tuple(layers), tuple(limitations)

    @staticmethod
    def _safe_attribute(value: Any, name: str) -> tuple[bool, Any]:
        try:
            return True, getattr(value, name)
        except Exception:
            return False, None

    @classmethod
    def _dependency_children(cls, node: Any) -> list[Any] | tuple[Any, ...] | None:
        available, raw_children = cls._safe_attribute(node, "dependencies")
        if not available:
            return None
        if raw_children is None:
            return ()
        # FastAPI's supported Dependant implementations expose exact ordered
        # list/tuple children. Never probe or materialize arbitrary iterables.
        if type(raw_children) not in {list, tuple}:
            return None
        return cast("list[Any] | tuple[Any, ...]", raw_children)

    @staticmethod
    def _limitation_source(handler: HandlerInfo) -> tuple[Path, int]:
        return handler.file_path, max(handler.line_number, 1)

    def _extract_dependency_graph(  # noqa: PLR0915
        self, route: Any, handler: HandlerInfo
    ) -> EndpointDependencyGraph:
        """Collect the declared FastAPI Dependant tree with deterministic hard bounds."""
        _effective_available, effective_route = self._safe_attribute(route, "starlette_route")
        _original_available, original_route = self._safe_attribute(route, "original_route")
        candidates: list[Any] = []
        for candidate in (effective_route, route, original_route):
            if candidate is not None and all(candidate is not seen for seen in candidates):
                candidates.append(candidate)
        root = None
        for candidate in candidates:
            available, candidate_root = self._safe_attribute(candidate, "dependant")
            if available and candidate_root is not None:
                root = candidate_root
                break
        source_path, source_line = self._limitation_source(handler)
        if root is None:
            return EndpointDependencyGraph(
                status=DependencyGraphStatus.UNAVAILABLE,
                limitations=(
                    DependencyGraphLimitation(
                        code="dependant_unavailable",
                        source_path=source_path,
                        source_line=source_line,
                        reason="FastAPI route exposes no effective dependant graph",
                    ),
                ),
            )
        roots = self._dependency_children(root)
        if roots is None:
            return EndpointDependencyGraph(
                status=DependencyGraphStatus.UNAVAILABLE,
                limitations=(
                    DependencyGraphLimitation(
                        code="dependencies_unavailable",
                        source_path=source_path,
                        source_line=source_line,
                        reason="FastAPI dependant exposes no traversable dependencies",
                    ),
                ),
            )

        occurrences: list[EndpointDependencyOccurrence] = []
        limitations: list[DependencyGraphLimitation] = []
        work = 0
        capped = False

        def limit(code: str, reason: str, span: DependencySourceSpan | None = None) -> None:
            path = span.file_path if span is not None else source_path
            line = span.start_line if span is not None else source_line
            limitations.append(
                DependencyGraphLimitation(
                    code=code,
                    source_path=path,
                    source_line=line,
                    reason=reason,
                )
            )

        def visit(  # noqa: PLR0912, PLR0915
            node: Any, index_path: tuple[int, ...], ancestors: frozenset[int]
        ) -> None:
            nonlocal work, capped
            if capped:
                return
            work += 1

            has_call, call = self._safe_attribute(node, "call")
            if not has_call:
                call = None
            callable_kind = self._callable_kind(call)
            module, qualname = self._callable_identity(call)
            span = self._dependency_source_span(call)
            _display_available, display = self._safe_attribute(call, "__name__")
            if not isinstance(display, str) or not display:
                display = type(call).__name__ if call is not None else "<unknown>"
            if len(display) > 512:
                limit(
                    "display_name_truncated",
                    f"dependency {index_path} display name exceeded its retention bound",
                    span,
                )
                display = display[:512]
            established = (
                has_call
                and callable_kind != DependencyCallableKind.UNKNOWN
                and module is not None
                and qualname is not None
                and "<locals>" not in qualname
                and span is not None
            )
            resolution = (
                DependencyResolutionStatus.ESTABLISHED
                if established
                else DependencyResolutionStatus.UNAVAILABLE
                if not has_call
                else DependencyResolutionStatus.CONDITIONAL
            )

            own_available, raw_own_scopes = self._safe_attribute(node, "own_oauth_scopes")
            legacy_available, raw_legacy_scopes = self._safe_attribute(node, "security_scopes")
            scopes_available = own_available or legacy_available
            declaration_local = own_available
            raw_scopes = raw_own_scopes if own_available else raw_legacy_scopes
            raw_scope_count = 0
            invalid_scope_member = False
            truncated_scope = False
            scopes_list: list[str] = []
            if raw_scopes is None:
                pass
            elif type(raw_scopes) in {list, tuple, set, frozenset}:
                raw_scope_count = len(raw_scopes)
                unordered = type(raw_scopes) in {set, frozenset}
                if unordered:
                    limit(
                        "security_scopes_unordered_shape",
                        f"dependency {index_path} exposes unordered security scopes",
                        span,
                    )
                if raw_scope_count > 256:
                    # Count first: every supported over-cap shape retains no
                    # member-level evidence and is never iterated or sorted.
                    limit(
                        "security_scope_count_truncated",
                        f"dependency {index_path} security-scope count exceeded 256",
                        span,
                    )
                else:
                    bounded_scopes: list[str] = []
                    for raw_scope in raw_scopes:
                        if type(raw_scope) is not str or not raw_scope:
                            invalid_scope_member = True
                        else:
                            if len(raw_scope) > 512:
                                truncated_scope = True
                            bounded_scopes.append(raw_scope)
                    # Validate the complete bounded collection before sorting or
                    # retaining any member-level evidence.
                    if not invalid_scope_member:
                        if unordered:
                            bounded_scopes.sort()
                        scopes_list = [scope[:512] for scope in bounded_scopes]
            else:
                limit(
                    "security_scopes_invalid_shape",
                    f"dependency {index_path} exposes invalid security-scope metadata",
                    span,
                )
            if invalid_scope_member:
                limit(
                    "security_scope_member_invalid",
                    f"dependency {index_path} contains a non-string or blank security scope",
                    span,
                )
            if truncated_scope:
                limit(
                    "security_scope_string_truncated",
                    f"dependency {index_path} contains an overlong security scope",
                    span,
                )
            scopes = tuple(scopes_list)
            declaration_kind = (
                DependencyDeclarationKind.SECURITY
                if declaration_local and scopes
                else DependencyDeclarationKind.DEPENDS_OR_SECURITY
                if scopes_available
                else DependencyDeclarationKind.UNKNOWN
            )
            has_use_cache, raw_use_cache = self._safe_attribute(node, "use_cache")
            use_cache = raw_use_cache if isinstance(raw_use_cache, bool) else None
            _name_available, raw_name = self._safe_attribute(node, "name")
            scope = (
                DependencyDeclarationScope.NESTED
                if len(index_path) > 1
                else DependencyDeclarationScope.PARAMETER
                if isinstance(raw_name, str) and raw_name
                else DependencyDeclarationScope.ASSEMBLY
            )
            callable_structure, structure_limitations = self._callable_structure(call)
            for structure_limitation in structure_limitations:
                limit(
                    structure_limitation,
                    f"dependency {index_path} callable structure metadata was malformed "
                    "or exceeded a retention bound",
                    span,
                )
            occurrences.append(
                EndpointDependencyOccurrence(
                    index_path=index_path,
                    parent_path=index_path[:-1],
                    depth=len(index_path),
                    order=len(occurrences),
                    declaration_scope=scope,
                    declaration_kind=declaration_kind,
                    callable_kind=callable_kind,
                    resolution_status=resolution,
                    display_name=display,
                    module=module,
                    qualname=qualname,
                    source_span=span,
                    security_scopes=scopes,
                    use_cache=use_cache,
                    callable_structure=callable_structure,
                )
            )
            if not established:
                limit(
                    "callable_identity_unavailable",
                    f"dependency {index_path} has no source-attested qualified callable identity",
                    span,
                )
            if not scopes_available:
                limit(
                    "declaration_kind_unavailable",
                    f"dependency {index_path} does not expose security-scope metadata",
                    span,
                )
            if not has_use_cache or use_cache is None:
                limit(
                    "cache_semantics_unavailable",
                    f"dependency {index_path} does not expose boolean use_cache semantics",
                    span,
                )

            node_id = id(node)
            if node_id in ancestors:
                limit("cycle", f"dependency {index_path} closes an internal dependant cycle", span)
                return
            children = self._dependency_children(node)
            if children is None:
                limit(
                    "nested_dependencies_unavailable",
                    f"dependency {index_path} exposes no traversable nested dependencies",
                    span,
                )
                return
            if len(index_path) >= self.dependency_max_depth:
                if children:
                    limit("depth_cap", f"dependency {index_path} reached the depth cap", span)
                return
            next_ancestors = ancestors | {node_id}
            for child_index in range(len(children)):
                if work >= self.dependency_max_work:
                    capped = True
                    limit("work_cap", "dependency graph traversal reached its work cap", span)
                    break
                if len(occurrences) >= self.dependency_max_nodes:
                    capped = True
                    limit("node_cap", "dependency graph traversal reached its node cap", span)
                    break
                visit(children[child_index], (*index_path, child_index), next_ancestors)
                if capped:
                    break

        for root_index in range(len(roots)):
            if work >= self.dependency_max_work:
                capped = True
                limit("work_cap", "dependency graph traversal reached its work cap")
                break
            if len(occurrences) >= self.dependency_max_nodes:
                capped = True
                limit("node_cap", "dependency graph traversal reached its node cap")
                break
            visit(roots[root_index], (root_index,), frozenset())
            if capped:
                break

        overrides = getattr(self._app, "dependency_overrides", None)
        try:
            overrides_visible = bool(overrides)
        except Exception:
            overrides_visible = True
        if overrides_visible:
            limit(
                "dependency_overrides_visible",
                "dependency overrides are visible; only the declared graph is modeled",
            )

        return EndpointDependencyGraph(
            status=(
                DependencyGraphStatus.CONDITIONAL
                if limitations
                else DependencyGraphStatus.ESTABLISHED
            ),
            occurrences=tuple(occurrences),
            limitations=tuple(limitations),
        )

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
        handler = self._get_handler_info(endpoint)
        return Endpoint(
            path=self._join_paths(prefix, path),
            methods=self._http_methods(route, original_route),
            handler=handler,
            name=getattr(route, "name", None),
            tags=list(getattr(route, "tags", None) or []),
            dependencies=self._extract_dependencies(route),
            dependency_graph=self._extract_dependency_graph(route, handler),
        )

    def _websocket_endpoint(self, route: Any, original_route: Any, prefix: str) -> Endpoint:
        metadata = self._effective_route_metadata(route)
        endpoint = self._require_route_endpoint(metadata, original_route)
        handler = self._get_handler_info(endpoint)
        return Endpoint(
            path=self._join_paths(prefix, self._require_route_path(metadata, original_route)),
            methods=[EndpointMethod.WEBSOCKET],
            handler=handler,
            name=getattr(metadata, "name", None),
            dependencies=self._extract_dependencies(metadata),
            dependency_graph=self._extract_dependency_graph(route, handler),
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

    def _extract_endpoints_in_process(self) -> list[Endpoint]:
        """Extract endpoints inside the disposable runtime worker process."""
        app = self._load_app()
        if not hasattr(app, "routes"):
            raise FastAPIExtractorError(
                f"Object '{self.app_variable}' does not have 'routes' attribute. "
                "Is it a FastAPI application?"
            )
        endpoints = self._walk_routes(app.routes)
        return sorted(endpoints, key=lambda endpoint: endpoint.identifier)

    @staticmethod
    def _kill_runtime_process_group(process: subprocess.Popen[str]) -> None:
        """Terminate the POSIX worker session, including non-detached descendants."""
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)

    @classmethod
    def _reap_runtime_process(cls, process: subprocess.Popen[str]) -> None:
        """Unconditionally stop the worker session and reap its direct process."""
        if process.stdin is not None and not process.stdin.closed:
            with suppress(OSError):
                process.stdin.close()
        cls._kill_runtime_process_group(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()

    def _read_runtime_result(self, result_path: Path, returncode: int) -> list[Endpoint]:
        if not result_path.is_file():
            raise FastAPIExtractorError(f"Runtime worker exited with status {returncode}")
        if result_path.stat().st_size > self.output_limit_bytes:
            raise FastAPIExtractorError("Runtime worker response exceeded the output limit")
        try:
            payload = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FastAPIExtractorError("Runtime worker returned an invalid response") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != 2:
            raise FastAPIExtractorError("Runtime worker returned an unsupported response")
        if payload.get("status") == "error":
            message = payload.get("message")
            detail = message if isinstance(message, str) and message else "unknown error"
            raise FastAPIExtractorError(f"Failed to load FastAPI app: {detail}")
        raw_endpoints = payload.get("endpoints")
        if payload.get("status") != "ok" or not isinstance(raw_endpoints, list):
            raise FastAPIExtractorError("Runtime worker returned an invalid endpoint inventory")
        if returncode != 0:
            raise FastAPIExtractorError(f"Runtime worker exited with status {returncode}")
        try:
            return [Endpoint.model_validate(item) for item in raw_endpoints]
        except (TypeError, ValueError) as exc:
            raise FastAPIExtractorError("Runtime worker returned invalid endpoint data") from exc

    def extract_endpoints(self) -> list[Endpoint]:
        """
        Extract endpoints in a fresh, bounded host subprocess.

        The subprocess isolates Python interpreter import state but is not a security
        sandbox. Use secure AST mode or the explicit VM runtime for untrusted code.
        """
        if os.name != "posix":
            raise FastAPIExtractorError(
                "Runtime subprocess isolation requires POSIX; use secure AST or VM mode"
            )
        request = {
            "schema_version": 2,
            "app_path": str(self.app_path),
            "app_variable": self.app_variable,
            "module_name": self.module_name,
            "output_limit_bytes": self.output_limit_bytes,
            "dependency_max_depth": self.dependency_max_depth,
            "dependency_max_nodes": self.dependency_max_nodes,
            "dependency_max_work": self.dependency_max_work,
        }
        with tempfile.TemporaryDirectory(prefix="fastapi-endpoint-runtime-") as temp_dir:
            result_path = Path(temp_dir) / "result.json"
            command = [
                sys.executable,
                "-B",
                "-X",
                f"pycache_prefix={Path(temp_dir) / 'pycache'}",
                "-m",
                "fastapi_endpoint_detector.parser.runtime_worker",
                "--result",
                str(result_path),
            ]
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    start_new_session=True,
                )
            except OSError as exc:
                raise FastAPIExtractorError(f"Could not start runtime worker: {exc}") from exc
            try:
                process.communicate(json.dumps(request), timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                raise FastAPIExtractorError(
                    f"Runtime extraction timed out after {self.timeout_seconds:g} seconds"
                ) from exc
            finally:
                self._reap_runtime_process(process)
            returncode = process.returncode
            if returncode is None:
                raise FastAPIExtractorError("Runtime worker did not terminate")
            return self._read_runtime_result(result_path, returncode)

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
