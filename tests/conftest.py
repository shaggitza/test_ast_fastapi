"""
Pytest configuration and shared fixtures.
"""

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_path() -> Path:
    """Get the path to the test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_app_path(fixtures_path: Path) -> Path:
    """Get the path to the sample FastAPI application."""
    return fixtures_path / "sample_app"


@pytest.fixture
def examples_path() -> Path:
    """Get the path to the examples directory."""
    return Path(__file__).parent.parent / "examples"


@pytest.fixture
def sample_fastapi_project(examples_path: Path) -> Path:
    """Get the path to the sample FastAPI project in examples."""
    return examples_path / "sample_fastapi_project"


@pytest.fixture
def sample_diffs_path(examples_path: Path) -> Path:
    """Get the path to the sample diff files."""
    return examples_path / "diffs"


@pytest.fixture
def simple_diff_content() -> str:
    """A simple diff for testing."""
    return """diff --git a/services/user_service.py b/services/user_service.py
index 1234567..abcdefg 100644
--- a/services/user_service.py
+++ b/services/user_service.py
@@ -10,6 +10,10 @@ def get_user(user_id: int) -> User:
     user = db.query(User).filter(User.id == user_id).first()
     return user
 
+def get_user_by_email(email: str) -> User:
+    user = db.query(User).filter(User.email == email).first()
+    return user
+
 def create_user(user_data: UserCreate) -> User:
     user = User(**user_data.dict())
     db.add(user)
"""


@pytest.fixture
def multi_file_diff_content() -> str:
    """A multi-file diff for testing."""
    # Note: Context lines must start with exactly one space character
    # The space is the diff marker, followed by the actual line content
    lines = [
        "diff --git a/models/user.py b/models/user.py",
        "index 1111111..2222222 100644",
        "--- a/models/user.py",
        "+++ b/models/user.py",
        "@@ -5,4 +5,5 @@ class User(BaseModel):",
        " " + "    id: int",  # space + content
        " " + "    name: str",
        " " + "    email: str",
        "+    is_active: bool = True",
        "diff --git a/services/user_service.py b/services/user_service.py",
        "index 3333333..4444444 100644",
        "--- a/services/user_service.py",
        "+++ b/services/user_service.py",
        "@@ -15,4 +15,9 @@ def create_user(user_data: UserCreate) -> User:",
        " " + "    db.add(user)",
        " " + "    db.commit()",
        " " + "    return user",
        "+",
        "+def deactivate_user(user_id: int) -> User:",
        "+    user = get_user(user_id)",
        "+    user.is_active = False",
        "+    return user",
    ]
    return "\n".join(lines) + "\n"
