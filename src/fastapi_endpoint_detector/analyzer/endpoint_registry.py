"""
Endpoint registry for storing and querying endpoints.
"""

from pathlib import Path
from typing import Iterator, Optional

from fastapi_endpoint_detector.models.endpoint import Endpoint, EndpointMethod


class EndpointRegistry:
    """
    Registry for storing and querying FastAPI endpoints.
    
    Provides efficient lookups by path, file, method, etc.
    """
    
    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._endpoints: list[Endpoint] = []
        self._by_path: dict[str, list[Endpoint]] = {}
        self._by_file: dict[Path, list[Endpoint]] = {}
        self._by_module: dict[str, list[Endpoint]] = {}
    
    def register(self, endpoint: Endpoint) -> None:
        """
        Register an endpoint in the registry.
        
        Args:
            endpoint: The endpoint to register.
        """
        self._endpoints.append(endpoint)
        
        # Index by path
        if endpoint.path not in self._by_path:
            self._by_path[endpoint.path] = []
        self._by_path[endpoint.path].append(endpoint)
        
        # Index by file
        file_path = endpoint.handler.file_path
        if file_path not in self._by_file:
            self._by_file[file_path] = []
        self._by_file[file_path].append(endpoint)
        
        # Index by module
        module = endpoint.handler.module
        if module not in self._by_module:
            self._by_module[module] = []
        self._by_module[module].append(endpoint)
    
    def register_many(self, endpoints: list[Endpoint]) -> None:
        """
        Register multiple endpoints.
        
        Args:
            endpoints: List of endpoints to register.
        """
        for endpoint in endpoints:
            self.register(endpoint)
    
    def get_all(self) -> list[Endpoint]:
        """Get all registered endpoints."""
        return list(self._endpoints)
    
    def get_by_path(self, path: str) -> list[Endpoint]:
        """
        Get endpoints by URL path.
        
        Args:
            path: The URL path to search for.
            
        Returns:
            List of endpoints with the given path.
        """
        return self._by_path.get(path, [])
    
    def get_by_file(self, file_path: Path | str) -> list[Endpoint]:
        """
        Get endpoints defined in a specific file.
        
        Args:
            file_path: Path to the file (can be relative or absolute).
            
        Returns:
            List of endpoints defined in that file.
        """
        if isinstance(file_path, str):
            file_path = Path(file_path)
        
        # Try to resolve if it exists
        try:
            resolved = file_path.resolve()
            if resolved in self._by_file:
                return self._by_file[resolved]
        except OSError:
            pass
        
        # Try exact match
        if file_path in self._by_file:
            return self._by_file[file_path]
        
        # Try matching by filename (for relative paths from diffs)
        file_str = str(file_path)
        for registered_path, endpoints in self._by_file.items():
            registered_str = str(registered_path)
            # Check if the diff path is a suffix of registered path
            if registered_str.endswith(file_str) or registered_str.endswith(file_str.lstrip("./")):
                return endpoints
            # Or check by filename match if diff path contains subdirs
            if file_path.name == registered_path.name and file_str in registered_str:
                return endpoints
        
        return []
    
    def get_by_module(self, module: str) -> list[Endpoint]:
        """
        Get endpoints defined in a specific module.
        
        Args:
            module: The module name.
            
        Returns:
            List of endpoints defined in that module.
        """
        return self._by_module.get(module, [])
    
    def get_by_method(self, method: EndpointMethod) -> list[Endpoint]:
        """
        Get endpoints by HTTP method.
        
        Args:
            method: The HTTP method.
            
        Returns:
            List of endpoints supporting that method.
        """
        return [e for e in self._endpoints if method in e.methods]
    
    def get_by_tag(self, tag: str) -> list[Endpoint]:
        """
        Get endpoints by OpenAPI tag.
        
        Args:
            tag: The tag to search for.
            
        Returns:
            List of endpoints with that tag.
        """
        return [e for e in self._endpoints if tag in e.tags]
    
    def get_by_line_range(
        self, 
        file_path: Path, 
        start_line: int, 
        end_line: int,
    ) -> list[Endpoint]:
        """
        Get endpoints whose handlers overlap with a line range.
        
        Args:
            file_path: Path to the file.
            start_line: Start of the line range.
            end_line: End of the line range.
            
        Returns:
            List of endpoints whose handlers are in the line range.
        """
        file_endpoints = self.get_by_file(file_path)
        overlapping: list[Endpoint] = []
        
        for endpoint in file_endpoints:
            handler = endpoint.handler
            handler_end = handler.end_line_number or handler.line_number
            
            # Check for overlap
            if handler.line_number <= end_line and handler_end >= start_line:
                overlapping.append(endpoint)
        
        return overlapping
    
    def find_endpoints_using_dependency(self, dependency_name: str) -> list[Endpoint]:
        """
        Find endpoints that use a specific Depends() dependency.
        
        Args:
            dependency_name: Name of the dependency function.
            
        Returns:
            List of endpoints using that dependency.
        """
        return [
            e for e in self._endpoints 
            if dependency_name in e.dependencies
        ]
    
    def __len__(self) -> int:
        """Return the number of registered endpoints."""
        return len(self._endpoints)
    
    def __iter__(self) -> Iterator[Endpoint]:
        """Iterate over all endpoints."""
        return iter(self._endpoints)
    
    def __contains__(self, endpoint: Endpoint) -> bool:
        """Check if an endpoint is registered."""
        return endpoint in self._endpoints
    
    @property
    def files(self) -> set[Path]:
        """Get all files containing endpoints."""
        return set(self._by_file.keys())
    
    @property
    def modules(self) -> set[str]:
        """Get all modules containing endpoints."""
        return set(self._by_module.keys())
    
    @property
    def paths(self) -> set[str]:
        """Get all unique endpoint paths."""
        return set(self._by_path.keys())
