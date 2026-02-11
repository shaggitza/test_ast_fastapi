"""
Class-Based Dependency Injection Example

This example demonstrates using class instances as dependencies,
a common pattern for services with state or configuration.
"""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException

app = FastAPI(title="Class-Based DI Example")


class DatabaseService:
    """Simulated database service with connection management."""

    def __init__(self) -> None:
        self.connection_string = "sqlite:///db.sqlite3"
        self.connected = False

    def connect(self) -> None:
        """Establish database connection."""
        self.connected = True

    def get_item(self, item_id: int) -> dict:
        """Retrieve an item from the database."""
        if not self.connected:
            self.connect()
        return {"id": item_id, "name": f"Item {item_id}", "price": 100.0}

    def list_items(self) -> list[dict]:
        """List all items from the database."""
        if not self.connected:
            self.connect()
        return [
            {"id": 1, "name": "Item 1", "price": 100.0},
            {"id": 2, "name": "Item 2", "price": 200.0},
        ]


class CacheService:
    """Simple in-memory cache service."""

    def __init__(self) -> None:
        self._cache: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        """Get value from cache."""
        return self._cache.get(key)

    def set(self, key: str, value: str) -> None:
        """Set value in cache."""
        self._cache[key] = value


# Dependency providers
def get_database() -> DatabaseService:
    """Dependency that returns a DatabaseService instance."""
    return DatabaseService()


def get_cache() -> CacheService:
    """Dependency that returns a CacheService instance."""
    return CacheService()


# Type aliases for cleaner endpoint signatures
DatabaseDep = Annotated[DatabaseService, Depends(get_database)]
CacheDep = Annotated[CacheService, Depends(get_cache)]


@app.get("/items")
def list_items(db: DatabaseDep) -> dict:
    """List all items using database service."""
    items = db.list_items()
    return {"items": items, "count": len(items)}


@app.get("/items/{item_id}")
def get_item(item_id: int, db: DatabaseDep, cache: CacheDep) -> dict:
    """Get a specific item, using cache if available."""
    cache_key = f"item:{item_id}"
    cached = cache.get(cache_key)

    if cached:
        return {"item": cached, "source": "cache"}

    item = db.get_item(item_id)
    cache.set(cache_key, str(item))
    return {"item": item, "source": "database"}


@app.post("/items/{item_id}/invalidate")
def invalidate_cache(item_id: int, cache: CacheDep) -> dict:
    """Invalidate cache for a specific item."""
    cache_key = f"item:{item_id}"
    cache.set(cache_key, "")
    return {"message": "Cache invalidated", "item_id": item_id}
