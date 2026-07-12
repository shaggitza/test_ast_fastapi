"""
Unit tests for orphan code detection feature.
"""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.models.diff import ChangeType, DiffFile, DiffHunk
from fastapi_endpoint_detector.models.report import OrphanChange


class TestOrphanChange:
    """Tests for the OrphanChange model."""
    
    def test_orphan_change_creation(self) -> None:
        """Test creating an OrphanChange instance."""
        orphan = OrphanChange(
            file_path="test/file.py",
            added_lines=[1, 2, 3],
            removed_lines=[10, 11],
            reason="Test orphan code",
        )
        
        assert orphan.file_path == "test/file.py"
        assert orphan.added_lines == [1, 2, 3]
        assert orphan.removed_lines == [10, 11]
        assert orphan.reason == "Test orphan code"
        assert orphan.total_lines == 5
    
    def test_orphan_change_format_lines(self) -> None:
        """Test formatting orphan lines for display."""
        orphan = OrphanChange(
            file_path="test/file.py",
            added_lines=[1, 2, 3],
            removed_lines=[10, 11],
        )
        
        formatted = orphan.format_lines()
        assert "Added: lines 1, 2, 3" in formatted
        assert "Removed: lines 10, 11" in formatted
    
    def test_orphan_change_format_lines_truncated(self) -> None:
        """Test formatting orphan lines with truncation."""
        # Create orphan with many lines
        added = list(range(1, 20))  # 19 lines
        orphan = OrphanChange(
            file_path="test/file.py",
            added_lines=added,
            removed_lines=[],
        )
        
        formatted = orphan.format_lines()
        assert "..." in formatted  # Should be truncated
        assert "(19 total)" in formatted
    
    def test_orphan_change_default_reason(self) -> None:
        """Test default reason for OrphanChange."""
        orphan = OrphanChange(
            file_path="test/file.py",
            added_lines=[1, 2],
            removed_lines=[],
        )
        
        assert "not related to any endpoint" in orphan.reason.lower()


class TestAnalysisReportWithOrphans:
    """Tests for AnalysisReport with orphan changes."""
    
    def test_orphan_count(self) -> None:
        """Test orphan_count property."""
        from fastapi_endpoint_detector.models.report import AnalysisReport
        
        report = AnalysisReport(
            app_path="/test/app.py",
            diff_source="test.diff",
            total_endpoints=5,
            orphan_changes=[
                OrphanChange(file_path="file1.py", added_lines=[1, 2], removed_lines=[]),
                OrphanChange(file_path="file2.py", added_lines=[3], removed_lines=[4, 5]),
            ],
        )
        
        assert report.orphan_count == 2
    
    def test_total_orphan_lines(self) -> None:
        """Test total_orphan_lines property."""
        from fastapi_endpoint_detector.models.report import AnalysisReport
        
        report = AnalysisReport(
            app_path="/test/app.py",
            diff_source="test.diff",
            total_endpoints=5,
            orphan_changes=[
                OrphanChange(file_path="file1.py", added_lines=[1, 2], removed_lines=[]),
                OrphanChange(file_path="file2.py", added_lines=[3], removed_lines=[4, 5]),
            ],
        )
        
        # 2 added in file1 + 1 added + 2 removed in file2 = 5 total
        assert report.total_orphan_lines == 5
    
    def test_empty_orphan_changes(self) -> None:
        """Test report with no orphan changes."""
        from fastapi_endpoint_detector.models.report import AnalysisReport
        
        report = AnalysisReport(
            app_path="/test/app.py",
            diff_source="test.diff",
            total_endpoints=5,
            orphan_changes=[],
        )
        
        assert report.orphan_count == 0
        assert report.total_orphan_lines == 0
