"""
Nested Dependencies Example

This example demonstrates dependencies that depend on other dependencies,
creating a dependency tree that the tool should properly track.
"""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Header

app = FastAPI(title="Nested Dependencies Example")


# Level 1: Base dependencies
def get_api_key(x_api_key: str | None = Header(None)) -> str:
    """Validate API key (base dependency)."""
    if not x_api_key or x_api_key != "secret-key":
        raise HTTPException(status_code=403, detail="Invalid API key")
    return x_api_key


def get_tenant_id(x_tenant_id: str | None = Header(None)) -> str:
    """Extract tenant ID (base dependency)."""
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="Tenant ID required")
    return x_tenant_id


# Level 2: Dependencies that use level 1 dependencies
def get_database_connection(
    api_key: Annotated[str, Depends(get_api_key)],
    tenant_id: Annotated[str, Depends(get_tenant_id)],
) -> dict:
    """Get database connection for tenant (depends on api_key and tenant_id)."""
    return {
        "connection": f"db://{tenant_id}",
        "authenticated": True,
        "api_key_valid": bool(api_key),
    }


def get_user_context(
    api_key: Annotated[str, Depends(get_api_key)],
) -> dict:
    """Get user context (depends on api_key)."""
    # In real app, decode JWT token to get user info
    return {
        "user_id": 123,
        "username": "admin",
        "roles": ["admin", "user"],
    }


# Level 3: Dependencies that use level 2 dependencies
def get_user_repository(
    db: Annotated[dict, Depends(get_database_connection)],
) -> dict:
    """Get user repository (depends on database connection)."""
    return {
        "repository": "UserRepository",
        "connection": db["connection"],
    }


def get_permission_checker(
    user: Annotated[dict, Depends(get_user_context)],
) -> dict:
    """Get permission checker (depends on user context)."""
    return {
        "checker": "PermissionChecker",
        "user_roles": user["roles"],
    }


# Level 4: Service that uses multiple level 3 dependencies
def get_user_service(
    repo: Annotated[dict, Depends(get_user_repository)],
    permissions: Annotated[dict, Depends(get_permission_checker)],
) -> dict:
    """Get user service (depends on repository and permissions)."""
    return {
        "service": "UserService",
        "repository": repo["repository"],
        "permissions": permissions["checker"],
    }


# Type aliases
DatabaseConnection = Annotated[dict, Depends(get_database_connection)]
UserContext = Annotated[dict, Depends(get_user_context)]
UserService = Annotated[dict, Depends(get_user_service)]


@app.get("/users")
def list_users(service: UserService) -> dict:
    """List users using the complete dependency chain."""
    return {
        "users": [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"},
        ],
        "service_info": service,
    }


@app.get("/users/{user_id}")
def get_user(user_id: int, db: DatabaseConnection, context: UserContext) -> dict:
    """Get a specific user using database and user context."""
    return {
        "user": {"id": user_id, "name": f"User {user_id}"},
        "database": db["connection"],
        "requested_by": context["username"],
    }


@app.post("/users")
def create_user(user_data: dict, service: UserService) -> dict:
    """Create a new user using the user service."""
    return {
        "user": user_data,
        "created_by": service["service"],
        "success": True,
    }
