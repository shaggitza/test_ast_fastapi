"""Bounded repository adapter for finite client and deployment observations.

The low-level recognizers accept source text. This module is the repository
adapter: it selects supported files, enforces file and byte budgets, records
read/decoding limits, and joins clients only to explicitly supplied trusted
server surfaces. It never discovers server origins or promotes observations to
affected endpoints.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from fastapi_endpoint_detector.analyzer.client_observations import (
    ClientObservation,
    ClientObservationIssue,
    ClientSurfaceMatch,
    EstablishedSurface,
    established_surfaces,
    extract_client_observation_inventory,
    join_established_surfaces,
)
from fastapi_endpoint_detector.analyzer.deployment_observations import (
    DeploymentObservation,
    extract_dockerfile_observations,
    extract_env_observations,
    extract_subprocess_observations,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from fastapi_endpoint_detector.models.endpoint import Endpoint

_CLIENT_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx", ".svelte"})
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "venv",
    }
)
_DEFAULT_CLIENT_PATTERNS = ("**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "**/*.svelte")
_DEFAULT_DEPLOYMENT_PATTERNS = (
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/Dockerfile*",
    "**/*.Dockerfile",
    "**/*.py",
)


@dataclass(frozen=True)
class SourceObservationIssue:
    """A repository source that was omitted by the bounded adapter."""

    source_path: str
    reason: str


@dataclass(frozen=True)
class ProjectObservationSnapshot:
    """Whole-root observations without effect on endpoint impact results."""

    root: Path
    client_observations: tuple[ClientObservation, ...]
    client_uncertainties: tuple[ClientObservationIssue, ...]
    deployment_observations: tuple[DeploymentObservation, ...]
    surface_matches: tuple[ClientSurfaceMatch, ...]
    scanned_files: int
    complete: bool
    issues: tuple[SourceObservationIssue, ...]
    client_include_patterns: tuple[str, ...]
    deployment_include_patterns: tuple[str, ...]
    trusted_surface_ids: tuple[str, ...]
    trusted_server_origins: tuple[tuple[str, str], ...]
    max_files: int
    max_file_bytes: int

    def to_dict(self) -> dict[str, object]:
        """Return stable JSON-compatible evidence while retaining queries/spans."""
        return {
            "schema_version": 1,
            "scope": "bounded_source_observations_only",
            "root": str(self.root),
            "complete": self.complete,
            "scanned_files": self.scanned_files,
            "source_selection": {
                "client_include_patterns": list(self.client_include_patterns),
                "deployment_include_patterns": list(self.deployment_include_patterns),
            },
            "trusted_surface_ids": list(self.trusted_surface_ids),
            "trusted_server_origins": dict(self.trusted_server_origins),
            "budgets": {"max_files": self.max_files, "max_file_bytes": self.max_file_bytes},
            "client_observations": [
                {
                    "source_path": item.source_path.as_posix(),
                    "line": item.line,
                    "protocol": item.protocol,
                    "method": item.method,
                    "route_path": item.route_path,
                    "query": item.query,
                    "literal_url": item.literal_url,
                    "origin": item.origin,
                    "start_offset": item.start_offset,
                    "end_offset": item.end_offset,
                    "certainty": "exact",
                }
                for item in self.client_observations
            ],
            "client_uncertainties": [
                {
                    "source_path": item.source_path.as_posix(),
                    "line": item.line,
                    "method": item.method,
                    "reason": item.reason,
                    "start_offset": item.start_offset,
                    "end_offset": item.end_offset,
                    "certainty": "uncertain",
                }
                for item in self.client_uncertainties
            ],
            "deployment_observations": [
                {
                    "source_path": item.source_path.as_posix(),
                    "line": item.line,
                    "kind": item.kind,
                    "key": item.key,
                    "value": list(item.value) if isinstance(item.value, tuple) else item.value,
                    "certainty": item.certainty,
                    "uncertainty": item.uncertainty,
                }
                for item in self.deployment_observations
            ],
            "surface_matches": [
                {
                    "source_path": item.observation.source_path.as_posix(),
                    "start_offset": item.observation.start_offset,
                    "end_offset": item.observation.end_offset,
                    "surface_id": item.surface_id,
                }
                for item in self.surface_matches
            ],
            "issues": [
                {"source_path": item.source_path, "reason": item.reason} for item in self.issues
            ],
            "limitations": [
                "Unsupported or dynamic recognized call shapes are listed as client uncertainties.",
                "Only exact client observations are eligible for explicit-origin route joins.",
                "A route match requires an explicitly supplied trusted surface "
                "and explicit origin.",
                "Observations do not change endpoint candidates, confidence, or route inventory.",
            ],
        }


def _is_candidate(path: Path) -> tuple[bool, str | None]:
    name = path.name
    lowered = name.lower()
    if path.suffix.lower() in _CLIENT_SUFFIXES:
        return True, "client"
    if name == ".env" or name.startswith(".env."):
        return True, "env"
    if (
        lowered == "dockerfile"
        or lowered.startswith("dockerfile.")
        or lowered.endswith(".dockerfile")
    ):
        return True, "dockerfile"
    if path.suffix.lower() == ".py":
        return True, "python"
    return False, None


def _matches_any(relative_path: str, patterns: Sequence[str]) -> bool:
    path = Path(relative_path)
    return any(
        path.match(pattern) or (pattern.startswith("**/") and path.match(pattern[3:]))
        for pattern in patterns
    )


def _normalize_trusted_origin(origin: str) -> str:
    if not isinstance(origin, str) or not origin or origin.strip() != origin:
        raise ValueError("trusted server origin must be a non-empty URL origin")
    try:
        parsed = urlsplit(origin)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("trusted server origin is malformed") from exc
    if (
        parsed.scheme.lower() not in {"http", "https", "ws", "wss"}
        or not parsed.netloc
        or hostname is None
        or parsed.netloc.endswith(":")
        or (port is not None and not 1 <= port <= 65535)
        or any(character.isspace() for character in parsed.netloc)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "trusted server origin must be an origin without path, query, or credentials"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _validate_source_patterns(patterns: Sequence[str]) -> None:
    for pattern in patterns:
        if (
            not isinstance(pattern, str)
            or not pattern
            or "\\" in pattern
            or "\x00" in pattern
            or Path(pattern).is_absolute()
            or ".." in Path(pattern).parts
        ):
            raise ValueError("source selection patterns must be relative, non-empty POSIX globs")
        open_class = False
        for character in pattern:
            if character == "[":
                if open_class:
                    raise ValueError("source selection pattern has an unmatched character class")
                open_class = True
            elif character == "]":
                if not open_class:
                    raise ValueError("source selection pattern has an unmatched character class")
                open_class = False
        if open_class:
            raise ValueError("source selection pattern has an unmatched character class")


def _read_bounded_regular_file(
    path: Path,
    max_file_bytes: int,
) -> tuple[bytes | None, str | None]:
    """Read one regular file without blocking or exceeding its byte budget."""
    descriptor: int | None = None
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            return None, "source is not a regular file"
        flags = os.O_RDONLY
        for flag_name in ("O_BINARY", "O_NONBLOCK", "O_NOFOLLOW"):
            flags |= getattr(os, flag_name, 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            return None, "source is not a regular file"
        if opened.st_size > max_file_bytes:
            return None, "maximum source-file size exceeded"

        contents = bytearray()
        while len(contents) <= max_file_bytes:
            remaining = max_file_bytes + 1 - len(contents)
            if remaining == 0:
                break
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            contents.extend(chunk)
        if len(contents) > max_file_bytes:
            return None, "maximum source-file size exceeded"
        return bytes(contents), None
    except OSError as exc:
        return None, f"source read failed: {type(exc).__name__}"
    finally:
        if descriptor is not None:
            os.close(descriptor)


def scan_project_observations(  # noqa: PLR0912, PLR0915
    root: Path | str,
    *,
    endpoints: Sequence[Endpoint] = (),
    trusted_server_origins: dict[str, str] | None = None,
    client_include_patterns: Sequence[str] = _DEFAULT_CLIENT_PATTERNS,
    deployment_include_patterns: Sequence[str] = _DEFAULT_DEPLOYMENT_PATTERNS,
    max_files: int = 10_000,
    max_file_bytes: int = 2_000_000,
) -> ProjectObservationSnapshot:
    """Scan supported source files in a repository without executing them.

    The limits bound both file count and per-file memory. Symlinks and paths
    resolving outside ``root`` are skipped. The caller owns the trust decision
    for every origin mapping. Mapping keys must identify established endpoints;
    unknown or conditional surface IDs are rejected.
    """
    if (
        isinstance(max_files, bool)
        or not isinstance(max_files, int)
        or isinstance(max_file_bytes, bool)
        or not isinstance(max_file_bytes, int)
        or max_files < 1
        or max_file_bytes < 1
    ):
        raise ValueError("source observation limits must be positive")
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise ValueError("source observation root must be a directory")
    _validate_source_patterns(client_include_patterns)
    _validate_source_patterns(deployment_include_patterns)

    origins = trusted_server_origins or {}
    if not isinstance(origins, dict) or any(
        not isinstance(surface_id, str) or not surface_id for surface_id in origins
    ):
        raise ValueError("trusted server origins must map non-empty surface IDs to origins")
    established = established_surfaces(list(endpoints))
    known_surface_ids = {surface.surface_id for surface in established}
    unknown_surface_ids = set(origins) - known_surface_ids
    if unknown_surface_ids:
        raise ValueError(
            "trusted origin references a surface that is not established: "
            + ", ".join(sorted(unknown_surface_ids))
        )
    normalized_origins = {
        surface_id: _normalize_trusted_origin(origin) for surface_id, origin in origins.items()
    }
    trusted_surfaces = tuple(
        EstablishedSurface(
            surface.surface_id,
            surface.path,
            surface.method,
            normalized_origins[surface.surface_id],
            True,
        )
        for surface in established
        if surface.surface_id in origins
    )

    client_observations: list[ClientObservation] = []
    client_uncertainties: list[ClientObservationIssue] = []
    deployment_observations: list[DeploymentObservation] = []
    issues: list[SourceObservationIssue] = []
    scanned_files = 0
    over_budget = False

    for directory, dirnames, filenames in os.walk(base, topdown=True, followlinks=False):
        current = Path(directory)
        retained_directories: list[str] = []
        for dirname in sorted(dirnames):
            if dirname in _SKIP_DIRS:
                continue
            child = current / dirname
            if child.is_symlink():
                issues.append(
                    SourceObservationIssue(
                        child.relative_to(base).as_posix(), "symlink directory was not followed"
                    )
                )
                continue
            retained_directories.append(dirname)
        dirnames[:] = retained_directories
        for filename in sorted(filenames):
            path = current / filename
            is_candidate, kind = _is_candidate(path)
            if not is_candidate:
                continue
            relative = path.relative_to(base).as_posix()
            include_patterns = (
                client_include_patterns if kind == "client" else deployment_include_patterns
            )
            if not _matches_any(relative, include_patterns):
                continue
            if path.is_symlink():
                issues.append(SourceObservationIssue(relative, "symlink source was not followed"))
                continue
            if scanned_files >= max_files:
                issues.append(SourceObservationIssue(relative, "maximum source-file count reached"))
                over_budget = True
                break
            scanned_files += 1
            try:
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(base):
                    issues.append(
                        SourceObservationIssue(relative, "path resolves outside source root")
                    )
                    continue
                source_bytes, read_issue = _read_bounded_regular_file(resolved, max_file_bytes)
                if read_issue is not None:
                    issues.append(SourceObservationIssue(relative, read_issue))
                    continue
                if source_bytes is None:
                    issues.append(SourceObservationIssue(relative, "source read failed: OSError"))
                    continue
                source = source_bytes.decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                issues.append(
                    SourceObservationIssue(relative, f"source read failed: {type(exc).__name__}")
                )
                continue

            if kind == "client":
                exact, uncertain = extract_client_observation_inventory(source, Path(relative))
                client_observations.extend(exact)
                client_uncertainties.extend(uncertain)
            elif kind == "env":
                deployment_observations.extend(extract_env_observations(source, Path(relative)))
            elif kind == "dockerfile":
                deployment_observations.extend(
                    extract_dockerfile_observations(source, Path(relative))
                )
            elif kind == "python":
                deployment_observations.extend(
                    extract_subprocess_observations(source, Path(relative))
                )
        if over_budget:
            break

    clients = tuple(
        sorted(
            client_observations,
            key=lambda item: (item.source_path.as_posix(), item.start_offset, item.end_offset),
        )
    )
    deployments = tuple(
        sorted(
            deployment_observations,
            key=lambda item: (item.source_path.as_posix(), item.line, item.kind, item.key or ""),
        )
    )
    client_issues = tuple(
        sorted(
            client_uncertainties,
            key=lambda item: (
                item.source_path.as_posix(),
                item.start_offset,
                item.end_offset,
            ),
        )
    )
    matches = join_established_surfaces(clients, trusted_surfaces)
    return ProjectObservationSnapshot(
        base,
        clients,
        client_issues,
        deployments,
        matches,
        scanned_files,
        not issues,
        tuple(issues),
        tuple(client_include_patterns),
        tuple(deployment_include_patterns),
        tuple(sorted({surface.surface_id for surface in trusted_surfaces})),
        tuple(sorted(normalized_origins.items())),
        max_files,
        max_file_bytes,
    )
