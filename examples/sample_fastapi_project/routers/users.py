"""User API Routes."""

from fastapi import APIRouter, Depends, HTTPException

from models.user import User, UserCreate, UserUpdate
from services.user_service import UserService
from utils.helpers import format_response

router = APIRouter()


def get_user_service() -> UserService:
    """Dependency injection for UserService."""
    return UserService()


@router.get("/")
def get_users(service: UserService = Depends(get_user_service)):
    """Get all users."""
    users = service.list_users()
    return format_response({"users": users})


@router.get("/{user_id}")
def get_user(user_id: int, service: UserService = Depends(get_user_service)):
    """Get a specific user by ID."""
    user = service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return format_response({"user": user})


@router.post("/")
def create_user(user: UserCreate, service: UserService = Depends(get_user_service)):
    """Create a new user."""
    created_user = service.create_user(user)
    return format_response({"user": created_user}, status="created")


@router.put("/{user_id}")
def update_user(
    user_id: int,
    user: UserUpdate,
    service: UserService = Depends(get_user_service),
):
    """Update an existing user."""
    existing = service.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    updated_user = service.update_user(user_id, user)
    return format_response({"user": updated_user})


@router.delete("/{user_id}")
def delete_user(user_id: int, service: UserService = Depends(get_user_service)):
    """Delete a user."""
    existing = service.get_user_by_id(user_id)
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")
    service.delete_user(user_id)
    return format_response({"deleted": True})
