"""
Security Dependencies Example

This example demonstrates FastAPI's security utilities and OAuth2 patterns,
commonly used in production applications.
"""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI(title="Security Dependencies Example")

# OAuth2 scheme for password-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# HTTP Bearer scheme for token-based authentication
bearer_scheme = HTTPBearer()


def decode_token(token: str) -> dict:
    """Decode and validate JWT token."""
    # In real app, use python-jose or similar library
    if token == "valid-token":
        return {
            "user_id": 123,
            "username": "johndoe",
            "email": "john@example.com",
            "scopes": ["read", "write"],
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> dict:
    """Get current user from OAuth2 token."""
    return decode_token(token)


def get_current_user_bearer(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)]
) -> dict:
    """Get current user from HTTP Bearer token."""
    return decode_token(credentials.credentials)


def get_current_active_user(
    current_user: Annotated[dict, Depends(get_current_user)]
) -> dict:
    """Verify user is active."""
    if current_user.get("disabled"):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_scope(required_scope: str):
    """Factory function to create scope-checking dependency."""

    def check_scope(user: Annotated[dict, Depends(get_current_user)]) -> dict:
        user_scopes = user.get("scopes", [])
        if required_scope not in user_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not enough permissions. Required: {required_scope}",
            )
        return user

    return check_scope


def get_admin_user(user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """Verify user has admin privileges."""
    if "admin" not in user.get("scopes", []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user


# Type aliases
CurrentUser = Annotated[dict, Depends(get_current_user)]
ActiveUser = Annotated[dict, Depends(get_current_active_user)]
AdminUser = Annotated[dict, Depends(get_admin_user)]


@app.get("/users/me")
def read_users_me(current_user: CurrentUser) -> dict:
    """Get current user's information."""
    return current_user


@app.get("/users/me/items")
def read_user_items(active_user: ActiveUser) -> dict:
    """Get current active user's items."""
    return {
        "user": active_user["username"],
        "items": [
            {"id": 1, "title": "Item 1"},
            {"id": 2, "title": "Item 2"},
        ],
    }


@app.post("/items")
def create_item(
    item: dict,
    user: Annotated[dict, Depends(require_scope("write"))],
) -> dict:
    """Create item (requires write scope)."""
    return {
        "item": item,
        "created_by": user["username"],
        "success": True,
    }


@app.delete("/users/{user_id}")
def delete_user(user_id: int, admin: AdminUser) -> dict:
    """Delete a user (requires admin privileges)."""
    return {
        "deleted_user_id": user_id,
        "deleted_by": admin["username"],
        "success": True,
    }


@app.get("/protected")
def protected_endpoint(
    bearer_user: Annotated[dict, Depends(get_current_user_bearer)]
) -> dict:
    """Protected endpoint using HTTP Bearer authentication."""
    return {
        "message": "Access granted",
        "user": bearer_user["username"],
    }
