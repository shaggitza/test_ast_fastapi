"""
Dependency graph construction using grimp.

This module uses the grimp library to build and query import dependency
graphs for Python packages.
"""

import sys
from pathlib import Path
from typing import Optional

import grimp


class DependencyGraphError(Exception):
    """Error during dependency graph operations."""
    pass


class DependencyGraph:
    """
    Build and query import dependency graphs using grimp.
    
    grimp provides efficient import graph construction and querying,
    handling all the complexity of Python's import system.
    
    Handles both single-package and multi-package (flat) project structures.
    """
    
    def __init__(self, package_path: Path) -> None:
        """
        Initialize the dependency graph.
        
        Args:
            package_path: Path to the Python package or project directory.
        """
        self.package_path = package_path.resolve()
        self._graphs: dict[str, grimp.ImportGraph] = {}
        self._all_modules: set[str] = set()
        self._import_map: dict[str, set[str]] = {}  # module -> imports
        self._imported_by_map: dict[str, set[str]] = {}  # module -> imported by
        self._original_sys_path: list[str] = []
        self._built = False
    
    def _setup_import_path(self) -> None:
        """Add package directory to sys.path for grimp."""
        self._original_sys_path = sys.path.copy()
        
        # Add the package directory itself so grimp can find subpackages
        pkg_dir = str(self.package_path)
        if pkg_dir not in sys.path:
            sys.path.insert(0, pkg_dir)
    
    def _restore_import_path(self) -> None:
        """Restore original sys.path."""
        sys.path = self._original_sys_path
    
    def _find_packages(self) -> list[str]:
        """
        Find all Python packages in the project directory.
        
        Returns:
            List of package names.
        """
        packages = []
        
        # Check for a main package (directory with __init__.py)
        if (self.package_path / "__init__.py").exists():
            packages.append(self.package_path.name)
            return packages
        
        # Otherwise, find all subdirectories that are packages
        for item in self.package_path.iterdir():
            if item.is_dir() and (item / "__init__.py").exists():
                packages.append(item.name)
        
        return packages
    
    def build(self) -> "DependencyGraph":
        """
        Build the import graph for all packages in the project.
        
        Returns:
            Self for method chaining.
            
        Raises:
            DependencyGraphError: If the graph cannot be built.
        """
        self._setup_import_path()
        
        try:
            packages = self._find_packages()
            
            if not packages:
                # No packages found - maybe a single-file module?
                raise DependencyGraphError(
                    f"No Python packages found in {self.package_path}"
                )
            
            # Build graph for each package with external packages included
            for pkg_name in packages:
                try:
                    graph = grimp.build_graph(pkg_name, include_external_packages=True)
                    self._graphs[pkg_name] = graph
                    
                    # Collect all modules
                    pkg_modules = graph.modules
                    self._all_modules.update(pkg_modules)
                    
                    # Build import maps
                    for module in pkg_modules:
                        imports = graph.find_modules_directly_imported_by(module)
                        self._import_map[module] = imports
                        
                        for imported in imports:
                            if imported not in self._imported_by_map:
                                self._imported_by_map[imported] = set()
                            self._imported_by_map[imported].add(module)
                            
                except Exception:
                    # Log but continue with other packages
                    pass
            
            self._built = True
            return self
            
        except Exception as e:
            raise DependencyGraphError(
                f"Failed to build dependency graph: {e}"
            ) from e
        finally:
            self._restore_import_path()
    
    def _ensure_built(self) -> None:
        """Ensure the graph has been built."""
        if not self._built:
            self.build()
    
    def get_all_modules(self) -> set[str]:
        """
        Get all modules in the package.
        
        Returns:
            Set of module names.
        """
        self._ensure_built()
        return self._all_modules.copy()
    
    def get_modules_imported_by(self, module: str) -> set[str]:
        """
        Get modules directly imported by a module.
        
        Args:
            module: The importing module name.
            
        Returns:
            Set of module names that are directly imported.
        """
        self._ensure_built()
        return self._import_map.get(module, set()).copy()
    
    def get_modules_that_import(self, module: str) -> set[str]:
        """
        Get modules that directly import a given module.
        
        Args:
            module: The imported module name.
            
        Returns:
            Set of module names that import the given module.
        """
        self._ensure_built()
        return self._imported_by_map.get(module, set()).copy()
    
    def get_upstream_modules(self, module: str) -> set[str]:
        """
        Get all modules that the given module depends on (transitively).
        
        Args:
            module: The module to check.
            
        Returns:
            Set of all upstream module names.
        """
        self._ensure_built()
        
        # BFS to find all upstream modules
        visited: set[str] = set()
        to_visit = list(self._import_map.get(module, set()))
        
        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
            visited.add(current)
            to_visit.extend(self._import_map.get(current, set()) - visited)
        
        return visited
    
    def get_downstream_modules(self, module: str) -> set[str]:
        """
        Get all modules that depend on the given module (transitively).
        
        Args:
            module: The module to check.
            
        Returns:
            Set of all downstream module names (modules affected if this changes).
        """
        self._ensure_built()
        
        # BFS to find all downstream modules
        visited: set[str] = set()
        to_visit = list(self._imported_by_map.get(module, set()))
        
        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
            visited.add(current)
            to_visit.extend(self._imported_by_map.get(current, set()) - visited)
        
        return visited
    
    def get_shortest_path(
        self, 
        from_module: str, 
        to_module: str,
    ) -> Optional[tuple[str, ...]]:
        """
        Find the shortest import chain between two modules.
        
        Args:
            from_module: The starting module.
            to_module: The target module.
            
        Returns:
            Tuple of module names representing the path, or None if no path exists.
        """
        self._ensure_built()
        
        # BFS to find shortest path
        if from_module == to_module:
            return (from_module,)
        
        visited: set[str] = {from_module}
        queue: list[tuple[str, ...]] = [(from_module,)]
        
        while queue:
            path = queue.pop(0)
            current = path[-1]
            
            for neighbor in self._import_map.get(current, set()):
                if neighbor == to_module:
                    return path + (neighbor,)
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + (neighbor,))
        
        return None
    
    def get_import_details(
        self, 
        importer: str, 
        imported: str,
    ) -> list[dict[str, str | int]]:
        """
        Get detailed information about imports between two modules.
        
        Args:
            importer: The importing module.
            imported: The imported module.
            
        Returns:
            List of dicts with import details (line numbers, etc).
        """
        self._ensure_built()
        
        # Find the package that contains this module
        for pkg_name, graph in self._graphs.items():
            if importer in graph.modules:
                try:
                    return graph.get_import_details(importer=importer, imported=imported)
                except Exception:
                    pass
        return []
    
    def module_to_file_path(self, module: str) -> Optional[Path]:
        """
        Convert a module name to its file path.
        
        Args:
            module: The module name (e.g., "package.submodule").
            
        Returns:
            Path to the module file, or None if not found.
        """
        # Try to find the module file
        parts = module.split(".")
        
        # Start from package path
        base_path = self.package_path
        
        # Construct potential paths
        module_path = base_path / "/".join(parts)
        
        # Check for package (__init__.py)
        if (module_path / "__init__.py").exists():
            return module_path / "__init__.py"
        
        # Check for module (.py file)
        py_path = module_path.with_suffix(".py")
        if py_path.exists():
            return py_path
        
        return None
    
    def file_path_to_module(self, file_path: Path | str) -> Optional[str]:
        """
        Convert a file path to its module name.
        
        Args:
            file_path: Path to a Python file.
            
        Returns:
            Module name, or None if not in the package.
        """
        if isinstance(file_path, str):
            file_path = Path(file_path)
        
        # Try to resolve if exists
        try:
            if file_path.exists():
                file_path = file_path.resolve()
        except OSError:
            pass
        
        # Try relative to package path
        try:
            relative = file_path.relative_to(self.package_path)
        except ValueError:
            # Try matching by suffix (for relative paths in diffs)
            file_str = str(file_path)
            for module in self._all_modules:
                module_path = self.module_to_file_path(module)
                if module_path and str(module_path).endswith(file_str):
                    return module
            return None
        
        # Convert path to module name
        parts = list(relative.parts)
        
        # Remove .py extension from last part
        if parts and parts[-1].endswith(".py"):
            if parts[-1] == "__init__.py":
                parts = parts[:-1]
            else:
                parts[-1] = parts[-1][:-3]
        
        return ".".join(parts) if parts else None
