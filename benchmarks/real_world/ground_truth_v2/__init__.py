"""Prediction-blind canonical ground-truth storage for benchmark v2."""

SCHEMA_VERSION = 1


class GroundTruthError(ValueError):
    """Raised when canonical truth input or state fails closed validation."""
