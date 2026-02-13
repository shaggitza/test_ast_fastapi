"""
Unit tests for the endpoint registry module.
"""

from pathlib import Path

import pytest

from fastapi_endpoint_detector.analyzer.endpoint_registry import EndpointRegistry
from fastapi_endpoint_detector.models.endpoint import (
    Endpoint,
    EndpointMethod,
    HandlerInfo,
)


@pytest.fixture
def sample_handler() -> HandlerInfo:
    """Create a sample handler info."""
    return HandlerInfo(
        name="get_users",
        module="routers.users",
        file_path=Path("/app/routers/users.py"),
        line_number=10,
        end_line_number=25,
    )


@pytest.fixture
def sample_endpoint(sample_handler: HandlerInfo) -> Endpoint:
    """Create a sample endpoint."""
    return Endpoint(
        path="/api/users",
        methods=[EndpointMethod.GET],
        handler=sample_handler,
        name="get_users",
        tags=["users"],
        dependencies=["get_db"],
    )


@pytest.fixture
def sample_endpoint_post(sample_handler: HandlerInfo) -> Endpoint:
    """Create a sample POST endpoint."""
    handler = HandlerInfo(
        name="create_user",
        module="routers.users",
        file_path=Path("/app/routers/users.py"),
        line_number=30,
        end_line_number=50,
    )
    return Endpoint(
        path="/api/users",
        methods=[EndpointMethod.POST],
        handler=handler,
        name="create_user",
        tags=["users"],
        dependencies=["get_db", "verify_token"],
    )


class TestEndpointRegistry:
    """Tests for the EndpointRegistry class."""

    def test_register_endpoint(self, sample_endpoint: Endpoint) -> None:
        """Test registering a single endpoint."""
        registry = EndpointRegistry()
        registry.register(sample_endpoint)

        assert len(registry) == 1
        assert sample_endpoint in registry

    def test_register_many(
        self,
        sample_endpoint: Endpoint,
        sample_endpoint_post: Endpoint,
    ) -> None:
        """Test registering multiple endpoints."""
        registry = EndpointRegistry()
        registry.register_many([sample_endpoint, sample_endpoint_post])

        assert len(registry) == 2

    def test_get_by_path(
        self,
        sample_endpoint: Endpoint,
        sample_endpoint_post: Endpoint,
    ) -> None:
        """Test getting endpoints by path."""
        registry = EndpointRegistry()
        registry.register_many([sample_endpoint, sample_endpoint_post])

        endpoints = registry.get_by_path("/api/users")
        assert len(endpoints) == 2

    def test_get_by_file(self, sample_endpoint: Endpoint) -> None:
        """Test getting endpoints by file."""
        registry = EndpointRegistry()
        registry.register(sample_endpoint)

        endpoints = registry.get_by_file(Path("/app/routers/users.py"))
        assert len(endpoints) == 1
        assert endpoints[0] == sample_endpoint

    def test_get_by_module(self, sample_endpoint: Endpoint) -> None:
        """Test getting endpoints by module."""
        registry = EndpointRegistry()
        registry.register(sample_endpoint)

        endpoints = registry.get_by_module("routers.users")
        assert len(endpoints) == 1

    def test_get_by_method(
        self,
        sample_endpoint: Endpoint,
        sample_endpoint_post: Endpoint,
    ) -> None:
        """Test getting endpoints by HTTP method."""
        registry = EndpointRegistry()
        registry.register_many([sample_endpoint, sample_endpoint_post])

        get_endpoints = registry.get_by_method(EndpointMethod.GET)
        assert len(get_endpoints) == 1

        post_endpoints = registry.get_by_method(EndpointMethod.POST)
        assert len(post_endpoints) == 1

    def test_get_by_tag(self, sample_endpoint: Endpoint) -> None:
        """Test getting endpoints by tag."""
        registry = EndpointRegistry()
        registry.register(sample_endpoint)

        endpoints = registry.get_by_tag("users")
        assert len(endpoints) == 1

        endpoints = registry.get_by_tag("nonexistent")
        assert len(endpoints) == 0

    def test_get_by_line_range(
        self,
        sample_endpoint: Endpoint,
        sample_endpoint_post: Endpoint,
    ) -> None:
        """Test getting endpoints by line range."""
        registry = EndpointRegistry()
        registry.register_many([sample_endpoint, sample_endpoint_post])

        # Line range overlapping with first endpoint (10-25)
        endpoints = registry.get_by_line_range(
            Path("/app/routers/users.py"),
            start_line=15,
            end_line=20,
        )
        assert len(endpoints) == 1
        assert endpoints[0].handler.name == "get_users"

        # Line range overlapping with second endpoint (30-50)
        endpoints = registry.get_by_line_range(
            Path("/app/routers/users.py"),
            start_line=35,
            end_line=40,
        )
        assert len(endpoints) == 1
        assert endpoints[0].handler.name == "create_user"

    def test_find_endpoints_using_dependency(
        self,
        sample_endpoint: Endpoint,
        sample_endpoint_post: Endpoint,
    ) -> None:
        """Test finding endpoints using a specific dependency."""
        registry = EndpointRegistry()
        registry.register_many([sample_endpoint, sample_endpoint_post])

        # Both use get_db
        endpoints = registry.find_endpoints_using_dependency("get_db")
        assert len(endpoints) == 2

        # Only POST uses verify_token
        endpoints = registry.find_endpoints_using_dependency("verify_token")
        assert len(endpoints) == 1
        assert endpoints[0].handler.name == "create_user"

    def test_properties(
        self,
        sample_endpoint: Endpoint,
        sample_endpoint_post: Endpoint,
    ) -> None:
        """Test registry properties."""
        registry = EndpointRegistry()
        registry.register_many([sample_endpoint, sample_endpoint_post])

        assert len(registry.files) == 1
        assert len(registry.modules) == 1
        assert len(registry.paths) == 1  # Same path, different methods
