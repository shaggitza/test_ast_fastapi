"""User Service - Business Logic Layer."""

from database.connection import get_database_connection
from models.user import User, UserCreate, UserUpdate


class UserService:
    """Service class for user operations."""

    def __init__(self):
        """Initialize the user service."""
        self.db = get_database_connection()
        self._users_cache: dict[int, User] = {}

    def list_users(self) -> list[User]:
        """Get all users from the database."""
        # Simulated database query
        return list(self._users_cache.values())

    def get_user_by_id(self, user_id: int) -> User | None:
        """Get a user by their ID."""
        return self._users_cache.get(user_id)

    def create_user(self, user_data: UserCreate) -> User:
        """Create a new user."""
        new_id = max(self._users_cache.keys(), default=0) + 1
        user = User(
            id=new_id,
            name=user_data.name,
            email=user_data.email,
            is_active=True,
        )
        self._users_cache[new_id] = user
        return user

    def update_user(self, user_id: int, user_data: UserUpdate) -> User | None:
        """Update an existing user."""
        if user_id not in self._users_cache:
            return None

        existing = self._users_cache[user_id]
        updated = User(
            id=existing.id,
            name=user_data.name if user_data.name else existing.name,
            email=user_data.email if user_data.email else existing.email,
            is_active=user_data.is_active if user_data.is_active is not None else existing.is_active,
        )
        self._users_cache[user_id] = updated
        return updated

    def delete_user(self, user_id: int) -> bool:
        """Delete a user by ID."""
        if user_id in self._users_cache:
            del self._users_cache[user_id]
            return True
        return False
