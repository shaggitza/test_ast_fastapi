"""
Function-Based Dependency Injection Example

This example demonstrates using simple functions as dependencies,
useful for extracting query parameters, headers, or simple utilities.
"""

from typing import Annotated

from fastapi import Depends, FastAPI, Query, Header, HTTPException

app = FastAPI(title="Function-Based DI Example")


def get_current_user(authorization: str | None = Header(None)) -> dict:
    """Extract and validate current user from authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    # Simulate token validation
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")

    token = authorization.replace("Bearer ", "")
    # In real app, validate token and fetch user
    return {"id": 1, "username": "testuser", "token": token}


def get_pagination(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum records to return"),
) -> dict:
    """Extract and validate pagination parameters."""
    return {"skip": skip, "limit": limit}


def verify_api_key(x_api_key: str | None = Header(None)) -> str:
    """Verify API key from custom header."""
    if not x_api_key:
        raise HTTPException(status_code=403, detail="API key required")

    # Simulate API key validation
    valid_keys = ["test-key-123", "test-key-456"]
    if x_api_key not in valid_keys:
        raise HTTPException(status_code=403, detail="Invalid API key")

    return x_api_key


# Type aliases for cleaner signatures
CurrentUser = Annotated[dict, Depends(get_current_user)]
Pagination = Annotated[dict, Depends(get_pagination)]
ApiKey = Annotated[str, Depends(verify_api_key)]


@app.get("/users/me")
def get_user_profile(user: CurrentUser) -> dict:
    """Get current user's profile."""
    return {"user": user, "profile_complete": True}


@app.get("/users")
def list_users(user: CurrentUser, pagination: Pagination, api_key: ApiKey) -> dict:
    """List users with pagination (requires admin API key)."""
    # Simulate fetching users with pagination
    users = [
        {"id": i, "username": f"user{i}"}
        for i in range(pagination["skip"], pagination["skip"] + pagination["limit"])
    ]
    return {
        "users": users,
        "pagination": pagination,
        "requested_by": user["username"],
    }


@app.post("/users/me/settings")
def update_settings(user: CurrentUser, settings: dict) -> dict:
    """Update current user's settings."""
    return {
        "user_id": user["id"],
        "settings": settings,
        "updated": True,
    }
