"""User Data Models."""

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    """Base user model with common attributes."""

    name: str
    email: str


class UserCreate(UserBase):
    """Model for creating a new user."""

    pass


class UserUpdate(BaseModel):
    """Model for updating a user (all fields optional)."""

    name: str | None = None
    email: str | None = None
    is_active: bool | None = None


class User(UserBase):
    """Complete user model with ID."""

    id: int
    is_active: bool = True

    class Config:
        """Pydantic configuration."""

        from_attributes = True
