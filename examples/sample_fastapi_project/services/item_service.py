"""Item Service - Business Logic Layer."""

from database.connection import get_database_connection
from models.item import Item, ItemCreate


class ItemService:
    """Service class for item operations."""

    def __init__(self):
        """Initialize the item service."""
        self.db = get_database_connection()
        self._items_cache: dict[int, Item] = {}

    def list_items(self, skip: int = 0, limit: int = 100) -> list[Item]:
        """Get all items with pagination."""
        items = list(self._items_cache.values())
        return items[skip : skip + limit]

    def get_item_by_id(self, item_id: int) -> Item | None:
        """Get an item by its ID."""
        return self._items_cache.get(item_id)

    def create_item(self, item_data: ItemCreate) -> Item:
        """Create a new item."""
        new_id = max(self._items_cache.keys(), default=0) + 1
        item = Item(
            id=new_id,
            name=item_data.name,
            description=item_data.description,
            price=item_data.price,
            in_stock=True,
        )
        self._items_cache[new_id] = item
        return item
