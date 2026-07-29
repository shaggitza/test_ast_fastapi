"""Deterministic project-local source inventory shared by static providers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


class SourceInventoryError(ValueError):
    """Raised when a deterministic source inventory cannot be constructed safely."""


@dataclass(frozen=True)
class SourceInventoryEntry:
    """One immutable project-local source snapshot entry."""

    relative_path: str
    path: Path
    module_name: str | None
    sha256: str
    size_bytes: int

    @property
    def is_python(self) -> bool:
        """Whether this entry is a Python implementation source."""
        return self.path.suffix == ".py"


@dataclass(frozen=True)
class SourceInventory:
    """Canonical deterministic source scope and immutable file fingerprint."""

    root: Path
    include_patterns: tuple[str, ...]
    exclude_patterns: tuple[str, ...]
    entries: tuple[SourceInventoryEntry, ...]
    fingerprint: str

    @classmethod
    def build(
        cls,
        root: Path,
        *,
        include_patterns: tuple[str, ...] = ("**/*.py",),
        exclude_patterns: tuple[str, ...] = (
            "**/test_*.py",
            "**/*_test.py",
            "**/tests/**",
            "**/__pycache__/**",
        ),
    ) -> SourceInventory:
        """Build one bounded-to-root snapshot without following source-file aliases."""
        try:
            canonical_root = root.expanduser().resolve(strict=True)
        except OSError as error:
            raise SourceInventoryError(
                f"source inventory root is unavailable: {root}: {error}"
            ) from error
        if not canonical_root.is_dir():
            raise SourceInventoryError(f"source inventory root is not a directory: {root}")
        if not include_patterns:
            raise SourceInventoryError("source inventory requires at least one include pattern")

        entries: list[SourceInventoryEntry] = []
        try:
            candidates = sorted(canonical_root.rglob("*"), key=lambda item: item.as_posix())
        except OSError as error:
            raise SourceInventoryError(f"source inventory enumeration failed: {error}") from error
        for candidate in candidates:
            try:
                if not candidate.is_file():
                    continue
                relative = candidate.relative_to(canonical_root).as_posix()
            except (OSError, ValueError) as error:
                raise SourceInventoryError(
                    f"source inventory candidate is outside its root: {candidate}"
                ) from error
            if any(part.startswith(".") or part == "__pycache__" for part in relative.split("/")):
                continue
            if not _matches_any(relative, include_patterns) or _matches_any(
                relative, exclude_patterns
            ):
                continue
            if candidate.is_symlink():
                # Project-local providers never follow source aliases outside the snapshot.
                continue
            try:
                raw = candidate.read_bytes()
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(canonical_root)
            except (OSError, ValueError) as error:
                raise SourceInventoryError(
                    f"source inventory file is unreadable or escapes its root: {relative}"
                ) from error
            entries.append(
                SourceInventoryEntry(
                    relative_path=relative,
                    path=resolved,
                    module_name=_module_name(relative) if resolved.suffix == ".py" else None,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    size_bytes=len(raw),
                )
            )

        payload = json.dumps(
            {
                "schema": 1,
                "root": str(canonical_root),
                "include_patterns": list(include_patterns),
                "exclude_patterns": list(exclude_patterns),
                "entries": [
                    {
                        "path": item.relative_path,
                        "sha256": item.sha256,
                        "size_bytes": item.size_bytes,
                    }
                    for item in entries
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return cls(
            root=canonical_root,
            include_patterns=include_patterns,
            exclude_patterns=exclude_patterns,
            entries=tuple(entries),
            fingerprint=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )

    def verify(self) -> None:
        """Reject source drift after this immutable inventory was captured."""
        current = SourceInventory.build(
            self.root,
            include_patterns=self.include_patterns,
            exclude_patterns=self.exclude_patterns,
        )
        if current.fingerprint != self.fingerprint:
            raise SourceInventoryError("source inventory changed after snapshot construction")

    @property
    def python_entries(self) -> tuple[SourceInventoryEntry, ...]:
        """Return Python sources in canonical relative-path order."""
        return tuple(item for item in self.entries if item.is_python)

    @property
    def python_paths(self) -> tuple[Path, ...]:
        """Return Python source paths in canonical relative-path order."""
        return tuple(item.path for item in self.python_entries)

    def contains(self, path: Path) -> bool:
        """Whether an existing path is an exact member of this snapshot."""
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            return False
        return any(item.path == resolved for item in self.entries)

    def allows_diff_path(self, path: Path) -> bool:
        """Whether a target/source diff path belongs to the configured source scope."""
        normalized = path.as_posix().lstrip("/")
        for prefix in ("a/", "b/"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
        candidates = {normalized}
        root_name = self.root.name
        marker = f"{root_name}/"
        if normalized.startswith(marker):
            candidates.add(normalized[len(marker) :])
        return any(
            _matches_any(candidate, self.include_patterns)
            and not _matches_any(candidate, self.exclude_patterns)
            for candidate in candidates
        )


def source_root_for_app(app_path: Path) -> Path:
    """Return the shared project root used by execution-free source providers."""
    resolved = app_path.expanduser().resolve()
    if resolved.is_dir():
        return resolved
    package = resolved.parent
    while (package / "__init__.py").is_file():
        package = package.parent
    return package


def _matches_any(relative_path: str, patterns: tuple[str, ...]) -> bool:
    path = PurePosixPath(relative_path)
    for pattern in patterns:
        normalized = pattern.replace("\\", "/")
        if path.match(normalized):
            return True
        if normalized.startswith("**/") and path.match(normalized[3:]):
            return True
    return False


def _module_name(relative_path: str) -> str:
    path = PurePosixPath(relative_path).with_suffix("")
    parts = list(path.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or PurePosixPath(relative_path).parent.name
