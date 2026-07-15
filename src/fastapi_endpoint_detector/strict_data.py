"""Safe structured-data loaders that reject duplicate mapping keys."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import yaml

if TYPE_CHECKING:
    from collections.abc import Callable


class DuplicateKeyError(ValueError):
    """Raised when serialized input repeats a mapping key."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    *,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    construct = cast("Callable[..., object]", loader.construct_object)
    for key_node, value_node in node.value:
        key = construct(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise DuplicateKeyError("mapping keys must be hashable scalars") from exc
        if duplicate:
            raise DuplicateKeyError(f"duplicate mapping key: {key!r}")
        result[key] = construct(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_yaml_unique(value: str) -> Any:
    """Safely parse YAML while rejecting duplicate keys at every depth."""
    return yaml.load(value, Loader=_UniqueKeyLoader)


def load_json_unique(value: str) -> Any:
    """Parse JSON while rejecting duplicate object keys at every depth."""

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise DuplicateKeyError(f"duplicate mapping key: {key!r}")
            result[key] = item
        return result

    return json.loads(value, object_pairs_hook=unique_object)
