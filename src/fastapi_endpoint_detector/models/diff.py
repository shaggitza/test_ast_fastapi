"""
Diff data models.

Models representing parsed diff files and changes.
"""

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class ChangeType(str, Enum):
    """Type of file change in a diff."""
    
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


class DiffHunk(BaseModel):
    """Represents a hunk (section of changes) in a diff."""
    
    source_start: int = Field(description="Starting line in source file")
    source_length: int = Field(description="Number of lines in source")
    target_start: int = Field(description="Starting line in target file")
    target_length: int = Field(description="Number of lines in target")
    added_lines: list[int] = Field(
        default_factory=list,
        description="Line numbers of added lines (in target)",
    )
    removed_lines: list[int] = Field(
        default_factory=list,
        description="Line numbers of removed lines (in source)",
    )
    
    class Config:
        frozen = True


class DiffFile(BaseModel):
    """Represents a single file in a diff."""
    
    path: Path = Field(description="Path to the file")
    change_type: ChangeType = Field(description="Type of change")
    source_path: Optional[Path] = Field(
        default=None,
        description="Original path (for renames)",
    )
    hunks: list[DiffHunk] = Field(
        default_factory=list,
        description="Hunks in this file",
    )
    added_lines: int = Field(default=0, description="Total lines added")
    removed_lines: int = Field(default=0, description="Total lines removed")
    
    class Config:
        frozen = True
    
    @property
    def is_python_file(self) -> bool:
        """Check if this is a Python file."""
        return self.path.suffix == ".py"
    
    def get_affected_line_ranges(self) -> list[tuple[int, int]]:
        """Get list of (start, end) line ranges affected by changes."""
        ranges: list[tuple[int, int]] = []
        for hunk in self.hunks:
            # For modifications/additions, use target lines
            if self.change_type in (ChangeType.MODIFIED, ChangeType.ADDED):
                ranges.append((hunk.target_start, hunk.target_start + hunk.target_length))
            # For deletions, use source lines
            elif self.change_type == ChangeType.DELETED:
                ranges.append((hunk.source_start, hunk.source_start + hunk.source_length))
        return ranges


class FileChange(BaseModel):
    """Aggregated information about changes in a file."""
    
    file: DiffFile = Field(description="The diff file information")
    affected_modules: list[str] = Field(
        default_factory=list,
        description="Module names affected by this change",
    )
    
    class Config:
        frozen = True
