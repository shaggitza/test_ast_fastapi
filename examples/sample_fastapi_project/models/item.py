"""Item Data Models."""

from pydantic import BaseModel


class ItemBase(BaseModel):
    """Base item model with common attributes."""

    name: str
    description: str | None = None
    price: float


class ItemCreate(ItemBase):
    """Model for creating a new item."""

    pass


class Item(ItemBase):
    """Complete item model with ID."""

    id: int
    in_stock: bool = True

    class Config:
        """Pydantic configuration."""

        from_attributes = True
