"""
FastAPI Example Application

This is a sample FastAPI application used for testing the
FastAPI Endpoint Change Detector tool.
"""

from fastapi import FastAPI

from routers import items, users
from utils.helpers import format_response

app = FastAPI(
    title="Sample API",
    description="A sample FastAPI application for testing endpoint detection",
    version="1.0.0",
)

# Include routers
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(items.router, prefix="/api/items", tags=["items"])


@app.get("/")
def root():
    """Health check endpoint."""
    return format_response({"status": "healthy", "version": "1.0.0"})


@app.get("/health")
def health_check():
    """Detailed health check endpoint."""
    return {
        "status": "healthy",
        "database": "connected",
        "cache": "connected",
    }
