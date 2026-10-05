"""
Unit tests for the diff parser module.
"""

import subprocess
from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.diff import ChangeType
from fastapi_endpoint_detector.parser.diff_parser import DiffParser, DiffParserError


class TestDiffParser:
    @staticmethod
    def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_real_git_mode_binary_and_rename_changes_keep_file_identity(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo with spaces"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        self._git(repo, "config", "user.email", "test@example.com")
        self._git(repo, "config", "user.name", "Test")
        (repo / "pkg").mkdir()
        (repo / "pkg" / "mode.py").write_text("value = 1\n", encoding="utf-8")
        (repo / "pkg" / "binary.py").write_bytes(b"\x00python\xff")
        (repo / "pkg" / "old.py").write_text("def route():\n    return 1\n", encoding="utf-8")
        self._git(repo, "add", "--", "pkg")
        self._git(repo, "commit", "-qm", "baseline")

        (repo / "pkg" / "mode.py").chmod(0o755)
        (repo / "pkg" / "new.py").write_text("def route():\n    return 1\n", encoding="utf-8")
        (repo / "pkg" / "old.py").unlink()
        (repo / "pkg" / "binary.py").write_bytes(b"\x00changed\xff")
        self._git(repo, "add", "-A")
        diff = self._git(
            repo,
            "-c",
            "core.quotePath=true",
            "diff",
            "--cached",
            "--no-ext-diff",
            "--find-renames",
            "--summary",
            "--patch",
            "HEAD",
        ).stdout

        parsed = DiffParser.parse_string(diff)
        by_path = {str(item.path): item for item in parsed}

        assert "pkg/mode.py" in by_path
        assert "pkg/binary.py" in by_path
        assert by_path["pkg/binary.py"].is_python_file
        assert any(item.source_path == Path("pkg/old.py") for item in parsed)
        assert all(item.get_side_qualified_lines() == ([], []) for item in parsed)

    def test_side_qualified_line_numbers_from_git_quoted_rename(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True
        )
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        original = repo / "caf\N{LATIN SMALL LETTER E WITH ACUTE}\told.py"
        original.write_bytes(b"def old():\n    return 1\n# retained\n")
        subprocess.run(["git", "-C", str(repo), "add", "--", str(original.name)], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "baseline"], check=True)
        renamed = repo / "caf\N{LATIN SMALL LETTER E WITH ACUTE}\tnew.py"
        original.rename(renamed)
        renamed.write_bytes(b"def new():\n    return 1\n# retained\n")
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        diff = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "core.quotePath=true",
                "diff",
                "--cached",
                "--no-ext-diff",
                "--find-renames",
                "HEAD",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

        parsed = DiffParser.parse_string(diff)

        assert len(parsed) == 1
        assert parsed[0].path == Path("café\tnew.py")
        assert parsed[0].source_path == Path("café\told.py")
        assert parsed[0].get_side_qualified_lines() == ([1], [1])

    def test_real_git_no_newline_markers_keep_source_and_target_lines(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        self._git(repo, "config", "user.email", "test@example.com")
        self._git(repo, "config", "user.name", "Test")
        source = repo / "app.py"
        source.write_bytes(b"old = 1")
        self._git(repo, "add", "--", "app.py")
        self._git(repo, "commit", "-qm", "baseline")

        source.write_bytes(b"new = 1")
        diff = self._git(repo, "diff", "--no-ext-diff", "--unified=0", "HEAD").stdout

        assert "\\ No newline at end of file" in diff
        parsed = DiffParser.parse_string(diff)
        assert DiffParser.get_changed_line_numbers(parsed[0]) == ([1], [1])

    def test_real_git_repository_prefixed_paths_strip_only_git_side_prefix(
        self, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        self._git(repo, "config", "user.email", "test@example.com")
        self._git(repo, "config", "user.name", "Test")
        source = repo / "pkg" / "module.py"
        source.parent.mkdir()
        source.write_text("value = 1\n", encoding="utf-8")
        self._git(repo, "add", "--", "pkg/module.py")
        self._git(repo, "commit", "-qm", "baseline")

        source.write_text("value = 2\n", encoding="utf-8")
        diff = self._git(
            repo,
            "diff",
            "--no-ext-diff",
            "--unified=0",
            "--src-prefix=a/repository/",
            "--dst-prefix=b/repository/",
            "HEAD",
        ).stdout

        parsed = DiffParser.parse_string(diff)
        assert parsed[0].path == Path("repository/pkg/module.py")
        assert parsed[0].source_path == Path("repository/pkg/module.py")

    def test_rename_preserves_old_path_and_python_identity(self) -> None:
        diff = """diff --git a/old.py b/new.txt
similarity index 100%
rename from old.py
rename to new.txt
"""

        parsed = DiffParser.parse_string(diff)

        assert parsed[0].path == Path("new.txt")
        assert parsed[0].source_path == Path("old.py")
        assert parsed[0].is_python_file

    def test_preserves_leading_characters_after_exact_git_prefix(self) -> None:
        diff = """diff --git a/backend/app.py b/backend/app.py
--- a/backend/app.py
+++ b/backend/app.py
@@ -1 +1 @@
-old = 1
+new = 1
"""

        parsed = DiffParser.parse_string(diff)

        assert parsed[0].path == Path("backend/app.py")
        assert parsed[0].source_path == Path("backend/app.py")

    def test_no_newline_markers_do_not_shift_changed_lines(self) -> None:
        diff = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-old = 1
\\ No newline at end of file
+new = 1
\\ No newline at end of file
"""

        parsed = DiffParser.parse_string(diff)

        assert DiffParser.get_changed_line_numbers(parsed[0]) == ([1], [1])

    @pytest.mark.parametrize(
        ("quoted_path", "expected"),
        [
            (r"a\tb.py", "a\tb.py"),
            (r"caf\303\251.py", "café.py"),
        ],
    )
    def test_decodes_git_quoted_paths(self, quoted_path: str, expected: str) -> None:
        diff = f"""diff --git "a/{quoted_path}" "b/{quoted_path}"
index 1111111..2222222 100644
--- "a/{quoted_path}"
+++ "b/{quoted_path}"
@@ -1 +1 @@
-old = 1
+new = 1
"""

        parsed = DiffParser.parse_string(diff)

        assert parsed[0].path == Path(expected)
        assert parsed[0].source_path == Path(expected)
        assert parsed[0].is_python_file

    """Tests for the DiffParser class."""

    def test_parse_simple_diff(self, simple_diff_content: str) -> None:
        """Test parsing a simple diff string."""
        diff_files = DiffParser.parse_string(simple_diff_content)

        assert len(diff_files) == 1
        assert diff_files[0].path == Path("services/user_service.py")
        assert diff_files[0].change_type == ChangeType.MODIFIED
        assert diff_files[0].added_lines > 0

    def test_parse_real_diff_file(self, sample_diffs_path: Path) -> None:
        """Test parsing a real git-generated diff file."""
        test_diff = sample_diffs_path / "test_handler.diff"
        if test_diff.exists():
            diff_files = DiffParser.parse_file(test_diff)
            assert len(diff_files) >= 1
            # Should contain users.py
            py_files = [f for f in diff_files if f.is_python_file]
            assert len(py_files) >= 1

    def test_get_changed_line_numbers(self, simple_diff_content: str) -> None:
        """Test extracting changed line numbers."""
        diff_files = DiffParser.parse_string(simple_diff_content)
        added, _removed = DiffParser.get_changed_line_numbers(diff_files[0])

        assert len(added) > 0  # Should have added lines
        assert all(isinstance(line, int) for line in added)

    def test_changed_byte_spans_are_column_qualified_on_both_sides(self) -> None:
        before = "label = 'é😀'; hidden = lambda: get_value() + 1"
        after = "label = 'é😀'; hidden = lambda: get_value()"
        diff = (
            "diff --git a/service.py b/service.py\n"
            "--- a/service.py\n"
            "+++ b/service.py\n"
            "@@ -1 +1 @@\n"
            f"-{before}\n"
            f"+{after}\n"
        )

        parsed = DiffParser.parse_string(diff)[0]
        source_changes = DiffParser.get_changed_byte_spans(parsed, side="source")
        target_changes = DiffParser.get_changed_byte_spans(parsed, side="target")

        expected_start = len(before[: before.index(" + 1")].encode("utf-8"))
        assert [
            (item.line_number, item.start_column, item.end_column) for item in source_changes
        ] == [(1, expected_start, len(before.encode("utf-8")))]
        assert target_changes == []

        inserted = after + " + 2"
        insertion_diff = diff.replace(f"-{before}\n", f"-{after}\n").replace(
            f"+{after}\n", f"+{inserted}\n"
        )
        inserted_file = DiffParser.parse_string(insertion_diff)[0]
        target_insertion = DiffParser.get_changed_byte_spans(inserted_file, side="target")
        assert [
            (item.line_number, item.start_column, item.end_column) for item in target_insertion
        ] == [(1, len(after.encode("utf-8")), len(inserted.encode("utf-8")))]

    def test_parse_file_not_found(self) -> None:
        """Test that parsing a non-existent file raises an error."""
        with pytest.raises(DiffParserError):
            DiffParser.parse_file(Path("/nonexistent/file.diff"))

    def test_parse_empty_string(self) -> None:
        """Test parsing an empty diff string."""
        diff_files = DiffParser.parse_string("")
        assert diff_files == []

    def test_get_python_files(self, sample_diffs_path: Path) -> None:
        """Test filtering to only Python files using real diff."""
        test_diff = sample_diffs_path / "test_handler.diff"
        if test_diff.exists():
            diff_files = DiffParser.parse_file(test_diff)
            python_files = DiffParser.get_python_files(diff_files)

            assert len(python_files) >= 1
            for f in python_files:
                assert f.is_python_file
