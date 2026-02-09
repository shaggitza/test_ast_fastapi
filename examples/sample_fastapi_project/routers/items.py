"""Item API Routes."""

from fastapi import APIRouter, Depends, HTTPException

from models.item import Item, ItemCreate
from services.item_service import ItemService
from utils.helpers import format_response

router = APIRouter()


def get_item_service() -> ItemService:
    """Dependency injection for ItemService."""
    return ItemService()


@router.get("/")
def get_items(
    skip: int = 0,
    limit: int = 100,
    service: ItemService = Depends(get_item_service),
):
    """Get all items with pagination."""
    items = service.list_items(skip=skip, limit=limit)
    return format_response({"items": items, "skip": skip, "limit": limit})


@router.get("/{item_id}")
def get_item(item_id: int, service: ItemService = Depends(get_item_service)):
    """Get a specific item by ID."""
    item = service.get_item_by_id(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return format_response({"item": item})


@router.post("/")
def create_item(item: ItemCreate, service: ItemService = Depends(get_item_service)):
    """Create a new item."""
    created_item = service.create_item(item)
    return format_response({"item": created_item}, status="created")
