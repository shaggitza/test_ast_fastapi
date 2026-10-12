"""Validation for bounded route-observation configuration."""

import pytest
from pydantic import ValidationError

from fastapi_endpoint_detector.config import Config, RouteObservationConfig


def test_route_observations_are_disabled_by_default() -> None:
    config = Config()

    assert config.analysis.route_observations.enabled is False
    assert config.analysis.route_observations.trusted_server_origins == {}
    assert config.analysis.route_observations.max_files == 10_000
    assert config.analysis.route_observations.max_file_bytes == 2_000_000
    assert "**/*.Dockerfile" in config.analysis.route_observations.deployment_include_patterns


def test_trusted_origins_are_explicit_and_canonicalized() -> None:
    config = RouteObservationConfig(
        enabled=True,
        trusted_server_origins={
            "api:routes.py:4:get": "HTTPS://Api.Example:443/",
            "ws:routes.py:8:websocket": "wss://stream.example",
        },
    )

    assert config.trusted_server_origins == {
        "api:routes.py:4:get": "https://api.example:443",
        "ws:routes.py:8:websocket": "wss://stream.example",
    }


@pytest.mark.parametrize(
    "values",
    [
        {"max_files": True},
        {"max_files": "3"},
        {"max_files": 0},
        {"max_files": 10_001},
        {"max_file_bytes": 0},
        {"max_file_bytes": 16 * 1024 * 1024 + 1},
        {"client_include_patterns": ["/absolute/*.ts"]},
        {"client_include_patterns": ["../outside/*.ts"]},
        {"client_include_patterns": ["./*.ts"]},
        {"client_include_patterns": ["C:\\outside\\*.ts"]},
        {"client_include_patterns": ["**/*.{ts,js}"]},
        {"client_include_patterns": ["**/[broken.ts"]},
        {"client_include_patterns": ["**/[].ts"]},
        {"deployment_include_patterns": [""]},
        {"trusted_server_origins": []},
        {"trusted_server_origins": {"surface": "https://api.example/path"}},
        {"trusted_server_origins": {"surface": "https://api.example?query=1"}},
        {"trusted_server_origins": {"surface": "https://api.example#fragment"}},
        {"trusted_server_origins": {"surface": "https://user:pass@api.example"}},
        {"trusted_server_origins": {"surface": "https://api.example:bad"}},
        {"trusted_server_origins": {"surface": "https://api.example:0"}},
        {"trusted_server_origins": {"surface": "https://api.example:"}},
        {"trusted_server_origins": {"": "https://api.example"}},
    ],
)
def test_rejects_malformed_route_observation_configuration(values: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        RouteObservationConfig(**values)


def test_enabled_observations_require_at_least_one_pattern() -> None:
    with pytest.raises(ValidationError):
        Config.model_validate(
            {
                "analysis": {
                    "route_observations": {
                        "enabled": True,
                        "client_include_patterns": [],
                        "deployment_include_patterns": [],
                    }
                }
            }
        )
