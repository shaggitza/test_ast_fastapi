"""Helper Utility Functions."""

from datetime import datetime
from typing import Any


def format_response(data: dict[str, Any], status: str = "success") -> dict[str, Any]:
    """Format API response with standard structure.

    Args:
        data: The response data payload.
        status: Response status string.

    Returns:
        Formatted response dictionary.
    """
    return {
        "status": status,
        "data": data,
        "timestamp": get_timestamp(),
    }


def get_timestamp() -> str:
    """Get current ISO format timestamp.

    Returns:
        Current timestamp as ISO format string.
    """
    return datetime.utcnow().isoformat()


def validate_id(id_value: int) -> bool:
    """Validate that an ID is positive.

    Args:
        id_value: The ID to validate.

    Returns:
        True if valid, False otherwise.
    """
    return isinstance(id_value, int) and id_value > 0


def paginate(items: list, skip: int = 0, limit: int = 100) -> list:
    """Apply pagination to a list of items.

    Args:
        items: List of items to paginate.
        skip: Number of items to skip.
        limit: Maximum number of items to return.

    Returns:
        Paginated subset of items.
    """
    return items[skip : skip + limit]
