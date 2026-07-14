"""SCIP-backed Python symbol and reverse-impact queries."""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SCIPAnalyzerError(RuntimeError):
    """Raised when the explicit SCIP backend cannot produce reliable evidence."""


@dataclass(frozen=True)
class SCIPDefinition:
    """A definition returned by ``scip-query outline``."""

    symbol: str
    short_name: str
    file_path: Path
    start_line: int  # one-based, inclusive
    end_line: int  # one-based, inclusive


@dataclass(frozen=True)
class SCIPReachedDefinition:
    """A reverse-reachable definition and its distance from the change."""

    definition: SCIPDefinition
    depth: int


@dataclass(frozen=True)
class SCIPOccurrence:
    """A source occurrence returned by ``scip-query refs``."""

    file_path: Path
    line: int  # one-based


@dataclass(frozen=True)
class SCIPReverseCallEdge:
    """A direct caller-to-callee edge proven at a source occurrence."""

    caller: SCIPDefinition
    callee: SCIPDefinition
    occurrence: SCIPOccurrence


class SCIPAnalyzer:
    """Run a pinned Sourcegraph Python SCIP index through ``scip-query``."""

    QUERY_VERSION = "0.16.0"
    PYTHON_INDEXER_VERSION = "0.6.6"
    MAX_DEPTH = 1000

    def __init__(self, project_root: Path, *, use_cache: bool = True, timeout: float = 300.0):
        self.project_root = project_root.resolve()
        self.use_cache = use_cache
        self.timeout = timeout
        self._outline_cache: dict[Path, tuple[SCIPDefinition, ...]] = {}
        self._base_method_cache: dict[str, tuple[SCIPDefinition, ...]] = {}
        self._reverse_call_edge_cache: dict[
            tuple[str, str, Path], tuple[SCIPReverseCallEdge, ...]
        ] = {}
        self._ast_cache: dict[Path, ast.Module | None] = {}
        self._module_paths: dict[str, Path] | None = None

    def _executable(self, name: str) -> str:
        executable = shutil.which(name)
        if executable is None:
            raise SCIPAnalyzerError(
                f"Missing {name!r}. Install scip-query@{self.QUERY_VERSION}, "
                f"@sourcegraph/scip-python@{self.PYTHON_INDEXER_VERSION}, and SCIP CLI."
            )
        return executable

    def _run(self, args: list[str], *, json_output: bool = False) -> Any:
        try:
            result = subprocess.run(
                args,
                cwd=self.project_root,
                env=os.environ.copy(),
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise SCIPAnalyzerError(f"SCIP command timed out: {args[0]}") from error
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
            raise SCIPAnalyzerError(f"SCIP command failed ({result.returncode}): {detail}")
        if not json_output:
            return result.stdout.strip()
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise SCIPAnalyzerError(f"SCIP command returned invalid JSON: {error}") from error
        if not isinstance(payload, dict) or "result" not in payload:
            raise SCIPAnalyzerError("SCIP JSON response has no result field")
        return payload["result"]

    def validate_tools(self) -> None:
        """Reject missing, moving, or empirically incorrect toolchains."""
        query = self._executable("scip-query")
        indexer = self._executable("scip-python")
        self._executable("scip")
        if shutil.which("scip-python-plus") is not None:
            raise SCIPAnalyzerError(
                "scip-python-plus is visible on PATH and may be selected by scip-query; "
                "remove it and install @sourcegraph/scip-python@0.6.6"
            )
        query_version = str(self._run([query, "--version"]))
        indexer_version = str(self._run([indexer, "--version"]))
        if self.QUERY_VERSION not in query_version:
            raise SCIPAnalyzerError(
                f"Unsupported scip-query version {query_version!r}; expected {self.QUERY_VERSION}"
            )
        if self.PYTHON_INDEXER_VERSION not in indexer_version:
            raise SCIPAnalyzerError(
                f"Unsupported scip-python version {indexer_version!r}; "
                f"expected {self.PYTHON_INDEXER_VERSION}"
            )

    def ensure_index(self, *, force: bool = False) -> None:
        _ = force  # Kept for backend API compatibility; pinned SCIP indexes are always rebuilt.
        self.validate_tools()
        # Always force the pinned indexer. Reusing an opaque scip-query cache could
        # silently consume an index built by the known-bad scip-python-plus.
        args = [
            self._executable("scip-query"),
            "reindex",
            "--language",
            "python",
            "--force",
            "--json",
        ]
        result = self._run(args, json_output=True)
        if not isinstance(result, dict) or "indexPath" not in result:
            raise SCIPAnalyzerError("scip-query reindex did not return an index path")
        if result.get("reused") is not False:
            raise SCIPAnalyzerError("scip-query unexpectedly reused an unverified cached index")
        shards = result.get("shards")
        if not isinstance(shards, list) or not shards:
            raise SCIPAnalyzerError("scip-query reindex did not report indexer provenance")
        commands: list[str] = []
        for shard in shards:
            if isinstance(shard, dict):
                command = shard.get("command")
                if isinstance(command, str):
                    commands.append(command)
        if commands and not any("scip-python index" in command for command in commands):
            raise SCIPAnalyzerError(f"Unexpected Python SCIP indexer provenance: {commands!r}")

    def _relative_file(self, file_path: Path, *, repository_relative: bool = False) -> Path:
        if file_path.is_absolute():
            try:
                return file_path.resolve().relative_to(self.project_root)
            except ValueError as error:
                raise SCIPAnalyzerError(
                    f"Changed file is outside SCIP project: {file_path}"
                ) from error
        candidate = file_path
        if repository_relative and self.project_root.name in candidate.parts:
            root_index = (
                len(candidate.parts) - 1 - candidate.parts[::-1].index(self.project_root.name)
            )
            stripped = Path(*candidate.parts[root_index + 1 :])
            if stripped.parts and (self.project_root / stripped).exists():
                return stripped
        if (self.project_root / candidate).exists():
            return candidate
        parts = candidate.parts
        for index in range(1, len(parts)):
            suffix = Path(*parts[index:])
            if (self.project_root / suffix).exists():
                return suffix
        return candidate

    def outline(self, file_path: Path) -> tuple[SCIPDefinition, ...]:
        relative = self._relative_file(file_path)
        if relative in self._outline_cache:
            return self._outline_cache[relative]
        result = self._run(
            [self._executable("scip-query"), "outline", relative.as_posix(), "--json"],
            json_output=True,
        )
        if not isinstance(result, list):
            raise SCIPAnalyzerError(f"Invalid outline result for {relative}")
        definitions: list[SCIPDefinition] = []

        def collect(items: list[object]) -> None:
            for item in items:
                if not isinstance(item, dict):
                    raise SCIPAnalyzerError(f"Malformed outline entry for {relative}")
                symbol = item.get("symbol")
                short_name = item.get("shortName")
                start = item.get("startLine")
                end = item.get("endLine")
                if not (
                    isinstance(symbol, str)
                    and isinstance(short_name, str)
                    and isinstance(start, int)
                    and isinstance(end, int)
                ):
                    raise SCIPAnalyzerError(f"Incomplete outline entry for {relative}")
                definitions.append(SCIPDefinition(symbol, short_name, relative, start + 1, end + 1))
                children = item.get("children", [])
                if not isinstance(children, list):
                    raise SCIPAnalyzerError(f"Malformed outline children for {relative}")
                collect(children)

        collect(result)
        source_path = self.project_root / relative
        try:
            tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        except (OSError, SyntaxError, UnicodeError):
            tree = None
        if tree is not None:
            callable_ends = {
                node.lineno: node.end_lineno
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.end_lineno is not None
            }
            definitions = [
                SCIPDefinition(
                    definition.symbol,
                    definition.short_name,
                    definition.file_path,
                    definition.start_line,
                    max(definition.end_line, callable_ends.get(definition.start_line, 0)),
                )
                for definition in definitions
            ]
        value = tuple(definitions)
        self._outline_cache[relative] = value
        return value

    def definitions_at(self, file_path: Path, lines: set[int]) -> tuple[SCIPDefinition, ...]:
        found: dict[str, SCIPDefinition] = {}
        relative = self._relative_file(file_path, repository_relative=True)
        definitions = self.outline(relative)
        for line in lines:
            containing = [item for item in definitions if item.start_line <= line <= item.end_line]
            if containing:
                narrowest = min(
                    containing,
                    key=lambda item: (item.end_line - item.start_line, -item.start_line),
                )
                found[narrowest.symbol] = narrowest
        return tuple(found.values())

    def _project_module_paths(self) -> dict[str, Path]:
        if self._module_paths is None:
            paths: dict[str, Path] = {}
            for path in self.project_root.rglob("*.py"):
                relative = path.relative_to(self.project_root).with_suffix("")
                parts = list(relative.parts)
                if parts and parts[-1] == "__init__":
                    parts.pop()
                module = ".".join(parts)
                if module:
                    paths[module] = relative.with_suffix(".py")
                    paths[f"{self.project_root.name}.{module}"] = relative.with_suffix(".py")
            self._module_paths = paths
        return self._module_paths

    def base_method_definitions(  # noqa: PLR0912
        self, definition: SCIPDefinition
    ) -> tuple[SCIPDefinition, ...]:
        """Resolve explicitly inherited base methods for one concrete method."""
        cached = self._base_method_cache.get(definition.symbol)
        if cached is not None:
            return cached
        parts = definition.short_name.split(":")
        if len(parts) < 3 or not parts[-1].endswith("()"):
            self._base_method_cache[definition.symbol] = ()
            return ()
        class_name = parts[-2]
        method_name = parts[-1][:-2]
        source = self.project_root / definition.file_path
        try:
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        except (OSError, SyntaxError, UnicodeError):
            self._base_method_cache[definition.symbol] = ()
            return ()
        imports: dict[str, tuple[str, str] | None] = {}
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom) and statement.module:
                for import_alias in statement.names:
                    local_name = import_alias.asname or import_alias.name
                    imported = (statement.module, import_alias.name)
                    existing = imports.get(local_name)
                    if local_name in imports and existing != imported:
                        imports[local_name] = None
                    else:
                        imports[local_name] = imported
        classes = [
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        if len(classes) != 1:
            self._base_method_cache[definition.symbol] = ()
            return ()
        module_paths = self._project_module_paths()
        found: dict[str, SCIPDefinition] = {}
        for base in classes[0].bases:
            if not isinstance(base, ast.Name):
                continue
            import_info = imports.get(base.id)
            base_path: Path | None
            if base.id in imports and import_info is None:
                continue
            if import_info is None:
                base_path = definition.file_path
                base_name = base.id
            else:
                base_path = module_paths.get(import_info[0])
                base_name = import_info[1]
            if base_path is None:
                continue
            suffix = f":{base_name}:{method_name}()"
            matches = [item for item in self.outline(base_path) if item.short_name.endswith(suffix)]
            if len(matches) == 1:
                found[matches[0].symbol] = matches[0]
        result = tuple(found.values())
        self._base_method_cache[definition.symbol] = result
        return result

    def _definition_for_affected(self, file_path: Path, short_name: str) -> SCIPDefinition | None:
        matches = [item for item in self.outline(file_path) if item.short_name == short_name]
        return matches[0] if len(matches) == 1 else None

    def _validated_project_file(self, value: str) -> tuple[Path, Path]:
        """Return a canonical project-relative path and its absolute source path."""
        if not value or "\x00" in value:
            raise SCIPAnalyzerError(f"Malformed SCIP reference path: {value!r}")
        supplied = Path(value)
        if supplied.is_absolute() or ".." in supplied.parts:
            raise SCIPAnalyzerError(f"SCIP reference path is outside project: {value!r}")
        try:
            absolute = (self.project_root / supplied).resolve(strict=True)
            relative = absolute.relative_to(self.project_root)
        except (OSError, ValueError) as error:
            raise SCIPAnalyzerError(f"Invalid SCIP reference path: {value!r}") from error
        if not absolute.is_file():
            raise SCIPAnalyzerError(f"SCIP reference path is not a file: {value!r}")
        return relative, absolute

    def _source_ast(self, relative: Path, absolute: Path) -> ast.Module | None:
        if relative not in self._ast_cache:
            try:
                self._ast_cache[relative] = ast.parse(
                    absolute.read_text(encoding="utf-8"), filename=str(absolute)
                )
            except (OSError, SyntaxError, UnicodeError):
                self._ast_cache[relative] = None
        return self._ast_cache[relative]

    @staticmethod
    def _call_terminal_name(call: ast.Call) -> str | None:
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return None

    def _caller_at_reference(
        self,
        relative: Path,
        absolute: Path,
        line: int,
        callee_name: str,
    ) -> SCIPDefinition | None:
        tree = self._source_ast(relative, absolute)
        if tree is None:
            return None
        enclosing_functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.end_lineno is not None
            and node.lineno <= line <= node.end_lineno
        ]
        if len(enclosing_functions) != 1:
            return None
        references = [
            node
            for node in ast.walk(tree)
            if (
                (isinstance(node, ast.Name) and node.id == callee_name)
                or (isinstance(node, ast.Attribute) and node.attr == callee_name)
            )
            and node.end_lineno is not None
            and node.lineno <= line <= node.end_lineno
        ]
        if len(references) != 1:
            return None
        reference = references[0]
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and self._call_terminal_name(node) == callee_name
            and any(child is reference for child in ast.walk(node.func))
        ]
        if len(calls) != 1:
            return None
        containing = [
            definition
            for definition in self.outline(relative)
            if definition.short_name.endswith("()")
            and definition.start_line <= line <= definition.end_line
        ]
        if not containing:
            return None
        narrowest_size = min(item.end_line - item.start_line for item in containing)
        narrowest = [
            item for item in containing if item.end_line - item.start_line == narrowest_size
        ]
        return narrowest[0] if len(narrowest) == 1 else None

    def reverse_call_edges(  # noqa: PLR0912
        self, callee: SCIPDefinition
    ) -> tuple[SCIPReverseCallEdge, ...]:
        """Return conservative direct callers proven by line-only reference evidence."""
        cache_key = (callee.symbol, callee.short_name, callee.file_path)
        cached = self._reverse_call_edge_cache.get(cache_key)
        if cached is not None:
            return cached
        result = self._run(
            [self._executable("scip-query"), "refs", callee.symbol, "--json"],
            json_output=True,
        )
        if not isinstance(result, dict) or result.get("matched") is not True:
            raise SCIPAnalyzerError(f"SCIP could not resolve referenced symbol: {callee.symbol}")
        resolved = result.get("resolved")
        if not isinstance(resolved, dict) or resolved.get("symbol") != callee.symbol:
            raise SCIPAnalyzerError(
                f"SCIP resolved the wrong refs seed for {callee.symbol!r}: {resolved!r}"
            )
        resolved_short_name = resolved.get("shortName")
        resolved_path = resolved.get("relativePath")
        if not isinstance(resolved_short_name, str) or not isinstance(resolved_path, str):
            raise SCIPAnalyzerError("Incomplete SCIP refs resolution")
        if resolved_short_name != callee.short_name:
            raise SCIPAnalyzerError("SCIP refs resolution has an inconsistent short name")
        resolved_relative, _ = self._validated_project_file(resolved_path)
        callee_relative, _ = self._validated_project_file(callee.file_path.as_posix())
        if resolved_relative != callee_relative:
            raise SCIPAnalyzerError("SCIP refs resolution has an inconsistent definition path")
        parts = callee.short_name.split(":")
        if not parts or not parts[-1].endswith("()"):
            raise SCIPAnalyzerError("SCIP refs callee is not a callable definition")
        callee_name = parts[-1][:-2]
        if type(result.get("totalMatches")) is not int or result["totalMatches"] != 1:
            raise SCIPAnalyzerError(
                f"SCIP refs seed was ambiguous for {callee.symbol!r}: "
                f"{result.get('totalMatches')!r} matches"
            )
        other_matches = result.get("otherMatches")
        references = result.get("references")
        if not isinstance(other_matches, list) or not isinstance(references, list):
            raise SCIPAnalyzerError("Invalid SCIP refs result")

        edges: set[SCIPReverseCallEdge] = set()
        for reference in references:
            if not isinstance(reference, dict):
                raise SCIPAnalyzerError("Malformed SCIP reference entry")
            reference_path = reference.get("relativePath")
            zero_based_line = reference.get("line")
            if not isinstance(reference_path, str) or type(zero_based_line) is not int:
                raise SCIPAnalyzerError("Incomplete SCIP reference entry")
            if zero_based_line < 0:
                raise SCIPAnalyzerError("SCIP reference line cannot be negative")
            relative, absolute = self._validated_project_file(reference_path)
            line = zero_based_line + 1
            caller = self._caller_at_reference(relative, absolute, line, callee_name)
            if caller is None:
                continue
            occurrence = SCIPOccurrence(relative, line)
            edges.add(SCIPReverseCallEdge(caller, callee, occurrence))

        value = tuple(
            sorted(
                edges,
                key=lambda edge: (
                    edge.caller.symbol,
                    edge.callee.symbol,
                    edge.occurrence.file_path.as_posix(),
                    edge.occurrence.line,
                ),
            )
        )
        self._reverse_call_edge_cache[cache_key] = value
        return value

    def affected(
        self, seed: SCIPDefinition, *, max_depth: int | None = None
    ) -> tuple[SCIPReachedDefinition, ...]:
        depth_limit = self.MAX_DEPTH if max_depth is None else max_depth
        result = self._run(
            [
                self._executable("scip-query"),
                "affected",
                seed.short_name,
                "--max-depth",
                str(depth_limit),
                "--json",
            ],
            json_output=True,
        )
        if not isinstance(result, dict) or result.get("matched") is not True:
            raise SCIPAnalyzerError(f"SCIP could not resolve changed symbol: {seed.symbol}")
        resolved = result.get("resolved")
        if not isinstance(resolved, dict) or resolved.get("symbol") != seed.symbol:
            raise SCIPAnalyzerError(
                f"SCIP resolved the wrong seed for {seed.symbol!r}: {resolved!r}"
            )
        if result.get("totalMatches") != 1:
            raise SCIPAnalyzerError(
                f"SCIP seed was ambiguous for {seed.symbol!r}: "
                f"{result.get('totalMatches')!r} matches"
            )
        reached: list[SCIPReachedDefinition] = [SCIPReachedDefinition(seed, 0)]
        raw_affected = result.get("affected", [])
        if not isinstance(raw_affected, list):
            raise SCIPAnalyzerError("Invalid affected-symbol list")
        for item in raw_affected:
            if not isinstance(item, dict):
                raise SCIPAnalyzerError("Malformed affected-symbol entry")
            file_name, short_name, depth = (
                item.get("file"),
                item.get("shortName"),
                item.get("depth"),
            )
            if not (
                isinstance(file_name, str)
                and isinstance(short_name, str)
                and isinstance(depth, int)
            ):
                raise SCIPAnalyzerError("Incomplete affected-symbol entry")
            definition = self._definition_for_affected(Path(file_name), short_name)
            if definition is None:
                raise SCIPAnalyzerError(
                    f"Could not uniquely resolve affected definition {short_name!r} in {file_name}"
                )
            reached.append(SCIPReachedDefinition(definition, depth))
        return tuple(reached)
