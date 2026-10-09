"""
Diff parser using the unidiff library.

This module wraps the unidiff library to parse unified diff files
and extract structured change information.
"""

import os
from pathlib import Path

from unidiff.patch import Hunk, PatchedFile, PatchSet

from fastapi_endpoint_detector.models.diff import (
    ChangeType,
    DiffFile,
    DiffHunk,
)


class DiffParserError(Exception):
    """Error during diff parsing."""

    pass


class DiffParser:
    """
    Parse unified diff files using the unidiff library.

    Supports parsing from files, strings, or stdin.
    """

    @staticmethod
    def _determine_change_type(patched_file: PatchedFile) -> ChangeType:
        """
        Determine the type of change for a patched file.

        Args:
            patched_file: A PatchedFile from unidiff.

        Returns:
            The ChangeType for this file.
        """
        if patched_file.is_added_file:
            return ChangeType.ADDED
        elif patched_file.is_removed_file:
            return ChangeType.DELETED
        elif patched_file.is_rename:
            return ChangeType.RENAMED
        else:
            return ChangeType.MODIFIED

    @staticmethod
    def _parse_hunk(hunk: Hunk) -> DiffHunk:
        """
        Parse a unidiff Hunk into our DiffHunk model.

        Args:
            hunk: A Hunk from unidiff.

        Returns:
            DiffHunk with line information.
        """
        added_lines: list[int] = []
        removed_lines: list[int] = []

        for line in hunk:
            # unidiff already distinguishes source-side and target-side
            # coordinates. Using those coordinates also avoids counting patch
            # metadata such as ``\\ No newline at end of file`` as context.
            if line.is_added and line.target_line_no is not None:
                added_lines.append(line.target_line_no)
            elif line.is_removed and line.source_line_no is not None:
                removed_lines.append(line.source_line_no)

        return DiffHunk(
            source_start=hunk.source_start,
            source_length=hunk.source_length,
            target_start=hunk.target_start,
            target_length=hunk.target_length,
            added_lines=added_lines,
            removed_lines=removed_lines,
        )

    @staticmethod
    def _parse_patched_file(patched_file: PatchedFile) -> DiffFile:
        """
        Parse a PatchedFile into our DiffFile model.

        Args:
            patched_file: A PatchedFile from unidiff.

        Returns:
            DiffFile with all hunk information.
        """
        change_type = DiffParser._determine_change_type(patched_file)

        # Get the path - use target for added/modified, source for deleted
        if change_type == ChangeType.DELETED:
            path = Path(DiffParser._strip_git_prefix(patched_file.source_file, "a/"))
        else:
            path = Path(DiffParser._strip_git_prefix(patched_file.target_file, "b/"))

        # Preserve the old-side path for every change that has a source file.
        source_path = None
        if change_type != ChangeType.ADDED:
            source_path = Path(DiffParser._strip_git_prefix(patched_file.source_file, "a/"))

        # Parse all hunks
        hunks = [DiffParser._parse_hunk(hunk) for hunk in patched_file]

        return DiffFile(
            path=path,
            change_type=change_type,
            source_path=source_path,
            hunks=hunks,
            added_lines=patched_file.added,
            removed_lines=patched_file.removed,
        )

    @staticmethod
    def _strip_git_prefix(path: str, prefix: str) -> str:
        """Decode a Git pathname and remove one exact side prefix."""
        return DiffParser._decode_git_path(path).removeprefix(prefix)

    @staticmethod
    def _decode_git_path(path: str) -> str:
        """Decode Git's double-quoted C-style pathname representation.

        Git quotes unusual pathnames and represents non-ASCII filesystem bytes
        with octal escapes when ``core.quotePath`` is enabled. Decode only that
        well-defined quoted form; ordinary paths are returned unchanged.
        """
        if len(path) < 2 or not path.startswith('"') or not path.endswith('"'):
            return path

        escaped = path[1:-1]
        decoded = bytearray()
        simple_escapes = {
            "a": b"\a",
            "b": b"\b",
            "f": b"\f",
            "n": b"\n",
            "r": b"\r",
            "t": b"\t",
            "v": b"\v",
            "\\": b"\\",
            '"': b'"',
        }
        index = 0

        while index < len(escaped):
            character = escaped[index]
            if character != "\\":
                decoded.extend(character.encode("utf-8"))
                index += 1
                continue

            index += 1
            if index >= len(escaped):
                decoded.extend(b"\\")
                break

            escape = escaped[index]
            if escape in "01234567":
                end = index + 1
                while end < len(escaped) and end < index + 3 and escaped[end] in "01234567":
                    end += 1
                decoded.append(int(escaped[index:end], 8))
                index = end
                continue

            replacement = simple_escapes.get(escape)
            if replacement is None:
                # Preserve unknown escapes rather than silently changing a
                # pathname produced by a non-Git diff generator.
                decoded.extend(b"\\")
                decoded.extend(escape.encode("utf-8"))
            else:
                decoded.extend(replacement)
            index += 1

        return os.fsdecode(bytes(decoded))

    @classmethod
    def parse_file(cls, diff_path: Path, encoding: str = "utf-8") -> list[DiffFile]:
        """
        Parse a diff file.

        Args:
            diff_path: Path to the diff file.
            encoding: File encoding (default: utf-8).

        Returns:
            List of DiffFile objects.

        Raises:
            DiffParserError: If parsing fails.
        """
        try:
            patch_set = PatchSet.from_filename(str(diff_path), encoding=encoding)
            return [cls._parse_patched_file(f) for f in patch_set]
        except Exception as e:
            raise DiffParserError(f"Failed to parse diff file {diff_path}: {e}") from e

    @classmethod
    def parse_string(cls, diff_content: str) -> list[DiffFile]:
        """
        Parse diff content from a string.

        Args:
            diff_content: The diff content as a string.

        Returns:
            List of DiffFile objects.

        Raises:
            DiffParserError: If parsing fails.
        """
        try:
            patch_set = PatchSet(diff_content)
            return [cls._parse_patched_file(f) for f in patch_set]
        except Exception as e:
            raise DiffParserError(f"Failed to parse diff content: {e}") from e

    @classmethod
    def parse(cls, source: Path | str) -> list[DiffFile]:
        """
        Parse diff from a file path or string.

        Args:
            source: Either a Path to a diff file or diff content as string.

        Returns:
            List of DiffFile objects.
        """
        if isinstance(source, Path):
            return cls.parse_file(source)
        elif isinstance(source, str):
            # Check if it looks like a file path
            potential_path = Path(source)
            if potential_path.exists() and potential_path.is_file():
                return cls.parse_file(potential_path)
            # Otherwise treat as diff content
            return cls.parse_string(source)
        else:
            raise DiffParserError(f"Invalid source type: {type(source)}")

    @classmethod
    def get_python_files(cls, diff_files: list[DiffFile]) -> list[DiffFile]:
        """
        Filter diff files to only Python files.

        Args:
            diff_files: List of DiffFile objects.

        Returns:
            List of DiffFile objects that are Python files.
        """
        return [f for f in diff_files if f.is_python_file]

    @classmethod
    def get_changed_line_numbers(
        cls,
        diff_file: DiffFile,
    ) -> tuple[list[int], list[int]]:
        """
        Get all changed line numbers from a diff file.

        Args:
            diff_file: A DiffFile object.

        Returns:
            Tuple of (added_lines, removed_lines).
        """
        added: list[int] = []
        removed: list[int] = []

        for hunk in diff_file.hunks:
            added.extend(hunk.added_lines)
            removed.extend(hunk.removed_lines)

        return added, removed
