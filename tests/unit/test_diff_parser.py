"""
Unit tests for the diff parser module.
"""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.diff import ChangeType
from fastapi_endpoint_detector.parser.diff_parser import DiffParser, DiffParserError


class TestDiffParser:
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
        added, removed = DiffParser.get_changed_line_numbers(diff_files[0])

        assert len(added) > 0  # Should have added lines
        assert all(isinstance(line, int) for line in added)

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
